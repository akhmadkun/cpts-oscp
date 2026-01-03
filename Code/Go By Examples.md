# self-paced labs

https://go.dev/learn/#self-paced-labs

# Hello World

`hello-world.go`
```go
package main

import "fmt"

func main(){
	fmt.Println("Hello World")
}
```

```bash
> go run ./hello-world.go
Hello Mom

> go build ./hello-world.go
> ls
hello-world  hello-world.go
> ./hello-world
Hello Mom
```

# Values

```go
package main

import "fmt"

func main(){
	fmt.Println("go" + "lang")

	fmt.Println("1+1 =", 1+1)
	fmt.Println("7.0/3.0 =", 7.0/3.0)

	fmt.Println(true && false)
	fmt.Println(true || false)
	fmt.Println(false && false)
	fmt.Println(!true)

}
```

```bash
> go run ./values.go
golang
1+1 = 2
7.0/3.0 = 2.3333333333333335
false
true
false
false
```

# Variables

```go
package main

import "fmt"

func main(){
	var a = "initial"
	fmt.Println(a)

	var b, c int = 1, 2
	fmt.Println(b,c)

	var d = true
	fmt.Println(d)

	var e int
	fmt.Println(e)

	f := "apple"
	fmt.Println(f)
}
```

```bash
> go run ./variables.go
initial
1 2
true
0
apple
```

# Constant

```go
package main

import (
	"fmt"
	"math"
)

const s string = "constant"

func main() {
	fmt.Println(s)

	const n = 50000000

	const d = 3e20 / n
	fmt.Println(d)

	fmt.Println(int64(d))

	fmt.Println(math.Sin(n))
}
```

```bash
> go run ./constant.go
constant
6e+12
6000000000000
0.8256467432733234
```

# Looping

```go
package main

import "fmt"

func main() {

	i := 1
	for i <= 3 {
		i = i + 1
	}

	for j := 0; j < 3; j++ {
		fmt.Println(j)
	}

	for i := range 3 {
		fmt.Println("range", i)
	}

	for {
		fmt.Println("loop")
		break
	}

	for n := range 6 {
		if n%2 == 0 {
			continue
		}
		fmt.Println(n)
	}
}

```

