package main

import (
    "fmt"
    "go-rados/rados"
    "go-rados/rbd"
)

func main() {
    var major, minor, patch int = rados.Version()
    fmt.Println("RADOS version", major, minor, patch)

    major, minor, patch = rbd.Version()
    fmt.Println("RBD version", major, minor, patch)
}
