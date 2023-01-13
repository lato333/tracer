// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
    "flag"
    "fmt"
    "net"
    "os"
    "encoding/json"
    "strconv"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf/rlimit"
    "gopkg.in/yaml.v2"

    containercollection "github.com/lato333/inspektor-gadget/pkg/container-collection"
    containerutils "github.com/lato333/inspektor-gadget/pkg/container-utils"
    runtimeclient "github.com/lato333/inspektor-gadget/pkg/container-utils/runtime-client"
    "github.com/lato333/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
    "github.com/lato333/inspektor-gadget/pkg/gadgets/trace/exec/types"
    tracercollection "github.com/lato333/inspektor-gadget/pkg/tracer-collection"
)

type Config struct {
    Fluentd struct {
        Server string `yaml:"server"`
        Port int `yaml:"port"`
    } `yaml:"fluentd"`

    Namespace string `yaml:"namespace"`
}
const traceName = "tracer"

// NewConfig returns a new decoded Config struct
func NewConfig(configPath string) (*Config, error) {
    // Create config structure
    config := &Config{}

    // Open config file
    file, err := os.Open(configPath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    // Init new YAML decode
    d := yaml.NewDecoder(file)

    // Start YAML decoding from file
    if err := d.Decode(&config); err != nil {
        return nil, err
    }

    return config, nil
}

// ValidateConfigPath just makes sure, that the path provided is a file,
// that can be read
func ValidateConfigPath(path string) error {
    s, err := os.Stat(path)
    if err != nil {
        return err
    }
    if s.IsDir() {
        return fmt.Errorf("'%s' is a directory, not a normal file", path)
    }
    return nil
}

// ParseFlags will create and parse the CLI flags
// and return the path to be used elsewhere
func ParseFlags() (string, error) {
    // String that contains the configured configuration path
    var configPath string

    // Set up a CLI flag called "-config" to allow users
    // to supply the configuration file
    flag.StringVar(&configPath, "config", "./tracer.yml", "path to config file")

    // Actually parse the flags
    flag.Parse()

    // Validate the path first
    if err := ValidateConfigPath(configPath); err != nil {
        return "", err
    }

    // Return the configuration path
    return configPath, nil
}
func main() {

    cfgPath, err := ParseFlags()
    if err != nil {
    fmt.Printf("failed to parse cmdline: %s\n", err)
        return
    }

    // read config
    cfg, err := NewConfig(cfgPath)
    if err != nil {
        fmt.Printf("failed to read config: %s\n", err)
        return
    }


    // In some kernel versions it's needed to bump the rlimits to
    // use run BPF programs.
    if err := rlimit.RemoveMemlock(); err != nil {
        fmt.Printf("failed rlimit.RemoveMemlock(): %s\n", err)
        return
    }

    c, err := net.Dial("tcp",cfg.Fluentd.Server + ":" + strconv.Itoa(cfg.Fluentd.Port) )

    if err != nil {
        fmt.Println(err)
        return
    }

    // Create and initialize the container collection
    containerCollection := &containercollection.ContainerCollection{}

    tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)

    if err != nil {
        fmt.Printf("failed to create trace-collection: %s\n", err)
        return
    }
    defer tracerCollection.Close()

    // Define the different options for the container collection instance
    opts := []containercollection.ContainerCollectionOption{
    // Indicate the callback that will be invoked each time
    // there is an event
    containercollection.WithPubSub(tracerCollection.TracerMapsUpdater()),

    // Get containers created with runc
    containercollection.WithRuncFanotify(),

    // Enrich events with Linux namespaces information
    // It's needed to be able to filter by containers in this example.
    containercollection.WithLinuxNamespaceEnrichment(),

    // Enrich those containers with data from the container
   // runtime. docker and containerd in this case.
   containercollection.WithMultipleContainerRuntimesEnrichment(
    []*containerutils.RuntimeConfig{
        //	{Name: runtimeclient.DockerName},
        {Name: runtimeclient.ContainerdName},
    }),
   }

    if err := containerCollection.Initialize(opts...); err != nil {
        fmt.Printf("failed to initialize container collection: %s\n", err)
        return
    }

    defer containerCollection.Close()


    // Define a callback to be called each time there is an event.
    eventCallback := func(event types.Event) {
        var data = map[string]string{
            "process": event.Comm,
            "pid": strconv.FormatUint(uint64(event.Pid), 10),
            "container": event.Container,
            "args": fmt.Sprint(event.Args),
            "retval": strconv.Itoa(event.Retval),
        }

        jsonStr, err := json.Marshal(data)
        if err != nil {
            fmt.Printf("Error: %s", err.Error())
        }

        _, err = c.Write([]byte(string(jsonStr)+"\n"))
        if err != nil {
            println("Write to server failed:", err.Error())
        }


        /*	fmt.Printf("A new %q process with pid %d was executed in container %q with args %q and reval %d\n",
     		event.Comm, event.Pid, event.Container, event.Args, event.Retval)*/
        fmt.Printf(string(jsonStr))
    }

    // Create a tracer instance. This is the glue piece that allows
    // this example to filter events by containers.
    containerSelector := containercollection.ContainerSelector{
        Namespace: cfg.Namespace,
    }

    if err := tracerCollection.AddTracer(traceName, containerSelector);
    err != nil {
        fmt.Printf("error adding tracer: %s\n", err)
        return
    }
    defer tracerCollection.RemoveTracer(traceName)

    // Get mount namespace map to filter by containers
    mountnsmap, err := tracerCollection.TracerMountNsMap(traceName)
    if err != nil {
        fmt.Printf("failed to get mountnsmap: %s\n", err)
        return
    }

    // Create the tracer
    tracer, err := tracer.NewTracer(&tracer.Config{MountnsMap: mountnsmap}, containerCollection, eventCallback)
    if err != nil {
        fmt.Printf("error creating tracer: %s\n", err)
        return
    }
    defer tracer.Stop()

    defer c.Close()
    // Graceful shutdown
    exit := make(chan os.Signal, 1)
          signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
          <-exit
}
