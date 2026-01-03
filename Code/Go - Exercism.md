# Packages

Go applications are organized in packages. A package is a collection of source files located in the same directory. All source files in a directory must share the same package name. When a package is imported, only entities (functions, types, variables, constants) whose names start with a capital letter can be used / accessed. The recommended style of naming in Go is that identifiers will be named using `camelCase`, except for those meant to be accessible across packages which should be `PascalCase`.

```go
package lasagna
```

# Variables

Go is statically-typed, which means all variables [must have a defined type](https://en.wikipedia.org/wiki/Type_system) at compile-time.

Variables can be defined by explicitly specifying a type:

```go
var explicit int // Explicitly typed
```

You can also use an initializer, and the compiler will assign the variable type to match the type of the initializer.

```go
implicit := 10   // Implicitly typed as an int
```

Once declared, variables can be assigned values using the `=` operator. Once declared, a variable's type can never change.

```go
count := 1 // Assign initial value
count = 2  // Update to new value

count = false // This throws a compiler error due to assigning a non `int` type
```

# Constants

Constants hold a piece of data just like variables, but their value cannot change during the execution of the program.

Constants are defined using the `const` keyword and can be numbers, characters, strings or booleans:

```go
const Age = 21 // Defines a numeric constant 'Age' with the value of 21
```

# Functions

Go functions accept zero or more parameters. Parameters must be explicitly typed, there is no type inference.

Values are returned from functions using the `return` keyword.

A function is invoked by specifying the function name and passing arguments for each of the function's parameters.

Note that Go supports two types of comments. Single line comments are preceded by `//` and multi-line comments are inserted between `/*` and `*/`.

```go
package greeting

// Hello is a public function.
func Hello (name string) string {
    return hi(name)
}

// hi is a private function.
func hi (name string) string {
    return "hi " + name
}
```

# Boolean

Boolean's in Go are represented by the predeclared boolean type `bool`, which values can be either `true` or `false`. It's a defined type.

```go
var closed bool    // boolean variable 'closed' implicitly initialized with 'false'
speeding := true   // boolean variable 'speeding' initialized with 'true'
hasError := false  // boolean variable 'hasError' initialized with 'false' 
```

Go supports three logical operators that can evaluate expressions down to Boolean values, returning either `true` or `false`.

| Operator   | What it means                                 |
| ---------- | --------------------------------------------- |
| `&&` (and) | It is true if both statements are true.       |
| \|\| (or)  | It is true if at least one statement is true. |
| `!` (not)  | It is true only if the statement is false.    |

# Package

In Go an application is organized in packages. A package is a collection of source files located in the same folder. All source files in a folder must have the same package name at the top of the file. By convention packages are named to be the same as the folder they are located in.

```go
package greeting
```

Go provides an extensive standard library of packages which you can use in your program using the `import` keyword. Standard library packages are imported using their name.

```go
package greeting

import "fmt"
```

An imported package is then addressed with the package name:

```go
world := "World"
fmt.Sprintf("Hello %s", world)
```

Go determines if an item can be called by code in other packages through how it is declared. To make a function, type, variable, constant or struct field externally visible (known as _exported_) the name must start with a capital letter.

```go
package greeting

// Hello is a public function (callable from other packages).
func Hello(name string) string {
    return "Hello " + name
}

// hello is a private function (not callable from other packages).
func hello(name string) string {
    return "Hello " + name
}
```

# String Formatting

Go provides an in-built package called `fmt` (format package) which offers a variety of functions to manipulate the format of input and output. The most commonly used function is `Sprintf`, which uses verbs like `%s` to interpolate values into a string and returns that string.

```go
import "fmt"

food := "taco"
fmt.Sprintf("Bring me a %s", food)
// Returns: Bring me a taco
```

In Go floating point values are conveniently formatted with Sprintf's verbs: `%g` (compact representation), `%e` (exponent) or `%f` (non exponent). All three verbs allow the field's width and numeric position to be controlled.

```go
import "fmt"

number := 6
fmt.Printf("%d\n", number)   // 6
fmt.Printf("%02d\n", number) // 06
fmt.Printf("%03d\n", number) // 006

pecahan := 4.3242
fmt.Printf("%f\n", pecahan) // 4.324200
fmt.Printf("%.2f\n", pecahan) // 4.32
fmt.Printf("%.3f\n", pecahan) // 4.324


```

You can find a full list of available verbs in the [format package documentation](https://pkg.go.dev/fmt).

`fmt` contains other functions for working with strings, such as `Println` which simply prints the arguments it receives to the console and `Printf` which formats the input in the same way as `Sprintf` before printing it.

# Documentation

In Go, comments play an important role in documenting code. They are used by the `godoc` command, which extracts these comments to create documentation about Go packages. A documentation comment should be a complete sentence that starts with the name of the thing being described and ends with a period.

Comments should precede packages as well as exported identifiers, for example exported functions, methods, package variables, constants, and structs, which you will learn more about in the next exercises.

A package-level variable can look like this:

```go
// TemperatureCelsius represents a certain temperature in degrees Celsius.
var TemperatureCelsius float64
```
## Package comments

Package comments should be written directly before a package clause (`package x`) and begin with `Package x ...` like this:

```go
// Package kelvin provides tools to convert
// temperatures to and from Kelvin.
package kelvin
```

## Function comments

A function comment should be written directly before the function declaration. It should be a full sentence that starts with the function name. For example, an exported comment for the function `Calculate` should take the form `Calculate ...`. It should also explain what arguments the function takes, what it does with them, and what its return values mean, ending in a period):

```go
// CelsiusFreezingTemp returns an integer value equal to the temperature at which water freezes in degrees Celsius.
func CelsiusFreezingTemp() int {
	return 0
}
```

---
# Switch

Like other languages, Go also provides a `switch` statement. Switch statements are a shorter way to write long `if ... else if` statements. To make a switch, we start by using the keyword `switch` followed by a value or expression. We then declare each one of the conditions with the `case` keyword. We can also declare a `default` case, that will run when none of the previous `case` conditions matched:

```go
operatingSystem := "windows"

switch operatingSystem {
case "windows":
    // do something if the operating system is windows
case "linux":
    // do something if the operating system is linux
case "macos":
    // do something if the operating system is macos
default:
    // do something if the operating system is none of the above
} 
```

One interesting thing about switch statements, is that the value after the `switch` keyword can be omitted, and we can have boolean conditions for each `case`:

```go
age := 21

switch {
case age > 20 && age < 30:
    // do something if age is between 20 and 30
case age == 10:
    // do something if age is equal to 10
default:
    // do something else for every other case
}
```

## Solution

```go
package blackjack

// ParseCard returns the integer value of a card following blackjack ruleset.
func ParseCard(card string) int {
	switch card {
	case "ace":
		return 11
	case "two":
		return 2
	case "three":
		return 3
	case "four":
		return 4
	case "five":
		return 5
	case "six":
		return 6
	case "seven":
		return 7
	case "eight":
		return 8
	case "nine":
		return 9
	case "ten", "jack", "queen", "king":
		return 10
	default:
		return 0
	}
}

// FirstTurn returns the decision for the first turn, given two cards of the
// player and one card of the dealer.
func FirstTurn(card1, card2, dealerCard string) string {
	tot := ParseCard(card1) + ParseCard(card2)
	switch {
	case tot == 22:
		return "P"
	case tot == 21:
		if ParseCard(dealerCard) >= 10 {
			return "S"
		}
		return "W"
	case tot <= 20 && tot >= 17:
		return "S"
	case tot <= 16 && tot >= 12:
		if ParseCard(dealerCard) >= 7 {
			return "H"
		}
		return "S"
	default:
		return "H"
	}
}

```