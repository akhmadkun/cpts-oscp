# Playground

https://www.jshero.net/en/playground.html

# Variables

```javascript
let firstname = 'Lata'
```

# Functions

```javascript
function hello(){
	return 'Hello world!'
}
```

```javascript
function a (){return 'Hello a!'}
function b (){return 'Hello b!'}
```

```javascript
function greet() {return 'Haydo!'}
let salutation = greet()
```

# Parameters

```javascript
function echo(input){
	return input
}
```

# Strings

```javascript
function greet(input){return 'Hello ' + input + '!'}
function greet(input){return "Hello " + input + "!"}
```

## Logging

```javascript
function log(){
	console.log('Hello Console!')
}

function log(input){
	console.log(input)
}

function shout(input){
	console.log(input + input)
	return input + input
}
```

## length

```javascript
function length(input){
	return input.length;
}
```

## Case

```javascript
function toCase(input){
	return input.toLowerCase() + '-' + input.toUpperCase()
}
```

## charAt()

To get a character from a string at a specified index, use the `charAt(index)` method:

```js
let char0 = 'Frantz'.charAt(0);
let char1 = 'Frantz'.charAt(1);
let char9 = 'Frantz'.charAt(9);
```

The first character has the index 0. So `char0` has the value `'F'` and `char1` has the value `'r'`. If the index is larger than the index of the last character, the empty string is returned. So `char9` has the value `''`.

## trim()

The `trim` method removes whitespaces from both ends of a string.

```js
let input = ' Rosa Parks ';
let name = input.trim();
```

`name` contains the string `'Rosa Parks'`. Notice that `input` still contains the string `' Rosa Parks '`.

## indexOf()

To determine the first occurrence of a string within another string, use the `indexOf` method:

```js
let n1 = 'bit'.indexOf('it');
let n2 = 'bit'.indexOf('js');
let n3 = 'bit'.indexOf('IT');
```

`n1` is `1`, because the starting position of `'it'` in `'bit'` is `1`. As usual, counting starts at 0. `indexOf` returns `-1` if the search string does not occur in the calling string. Thus `n2` is `-1`. The `indexOf` method is case sensitive. So `n3` is also `-1`.

The `indexOf` method allows you to specify the position from which the search should start. This is done with a second parameter.

```js
let n1 = 'White Rabbit'.indexOf('it', 1);
let n2 = 'White Rabbit'.indexOf('it', 3);
```

The first `'it'` in `'White Rabbit'` has the index `2`. Starting our search at position `1` it will be found. `n1` is `2`. The second `'it'` in `'White Rabbit'` has the index `10`. Starting our search at position `3` it will be found. `n2` is `10`.

### Exercise

Write a function `secondIndexOf`, taking two strings and determining the second occurrence of the second string in the first string. If the search string does not occur twice, `-1` should be returned.

```javascript
function secondIndexOf(a,b){
	return a.indexOf(b, a.indexOf(b)+1)
}
```

## substr()

The `substr` method extracts a substring from a string:

```js
let see = 'see and stop'.substr(0, 3);
let and = 'see and stop'.substr(4, 3);
let stop = 'see and stop'.substr(8);
```

The first parameter specifies the position at which to start extracting. The second parameter specifies the number of characters to extract. If the second parameter is not set, all the characters from start position to the end of the string are extracted.

## replace()

The `replace` method replaces a substring with another:

```js
let str = 'JavaScript';
let newstr = str.replace('Java', 'ECMA');
```

`'Java'` is replaced with `'ECMA'`. Thus `newstr` has the value `'ECMAScript'`. The original string remains unchanged. Only the first occurrence is replaced:

```js
let newstr = 'Dada'.replace('a', 'i');
```

`newstr` has the value `'Dida'` and not `'Didi'`.

# Numbers

Numbers are represented by simple numerals. They can have a decimal point and a minus sign.

```js
let x1 = 1;
let x2 = 1.0;
let x3 = 3.14;
let x4 = -1;
```

`1` and `1.0` are the same number. You can calculate with numbers. The four basic arithmetics adding, subtracting, multiplying and dividing are represented by `+ - *` and `/`.

```js
let x1 = 6;
let x2 = 2;
let x3 = x1 + x2;
let x4 = x1 - x2;
let x5 = x1 * x2;
let x6 = x1 / x2;
```

The variables `x3` to `x6` thus have the values `8`, `4`, `12` and `3`.

## Increment

n programming, you often want to increase or decrease a counter by one. This can easily be done with the increment or decrement operator.

```js
let x = 1;
x++; // x == 2
let y = 10;
y--; // y == 9
```

## Modulo

Another arithmetic operator is modulo. It calculates the remainder of a division and is represented by `%`.

```js
let x = 7 % 2;
let y = 20 % 3;
```

7 divided by 2 is 3 with remainder 1. `x` is `1`. 20 divided by 3 is 6 with remainder 2. `y` is `2`.

## Parentheses

Just as in mathematics, the order of operations rules are valid in JavaScript. Multiplication and division are performed before addition and subtraction. With parentheses you can specify the order of operations.

```js
let x1 = 3 + 4 * 2;
let x2 = (3 + 4) * 2;
```

`x1` is `11` and `x2` is `14`.

# Math

Many mathematical functions are grouped together in the `Math` object. For example, `Math.sqrt(x)` returns the square root and `Math.pow(x, y)` calculates x to the power of y.

```
let y1 = Math.sqrt(9);
let y2 = Math.pow(10, 3);
```

`y1` has the value `3` and `y2` has the value `1000` (10³ = 10 * 10 * 10 = 1000).

## min and max

The minimum and maximum of a set of numbers can be calculated with `Math.min()` and `Math.max()`:

```js
let min = Math.min(5, 7);
let max = Math.max(3, 9, 2);
```

`min` receives the value `5` and `max` the value `9`. The special: Both functions can be called with an arbitrary number of arguments.

## PI

Besides functions `Math` offers some mathematical constants. `Math.PI` gives π (roughly 3.14) and `Math.E` gives Euler's number e (roughly 2.71).

```js
function area(radius){
	return Math.PI * Math.pow(radius,2)
}
```

## Rounding

If you want to round a number, you can use the `Math.round()`, `Math.floor()` and `Math.ceil()` functions.

```js
let a = Math.round(5.49);
let b = Math.round(4.5);
let c = Math.floor(5.99);
let d = Math.ceil(4.01);
```

`Math.round()` rounds a number to the nearest integer, `Math.floor()` rounds a number downwards to the nearest integer and `Math.ceil()` rounds a number upwards to the nearest integer. Therefore, the variables `a` to `d` all get the value `5`.

## Random

`Math.random()` returns a pseudo-random number between 0 (inclusive) and 1 (exclusive).

```js
let x = Math.random();
```

`x` could, for example, get the value `0.6206372241429993`. Each call of `Math.random()` generates a new random number. The numbers are equally distributed between 0 and 1. They are called pseudo-random numbers, because they look random but are still calculated. If you want to get random numbers in another range or with a different distribution, you have to transform the numbers generated by `Math.random()` adequately. This should be practiced now.

## parseInt()

Sometimes you want to read a number from a string. In case of an integer (..., -2, -1, 0, 1, 2, ..) you can use the `parseInt` function. The following examples return `19` or `-19`:

```js
let n1 = parseInt('19', 10);
let n2 = parseInt('+19', 10);
let n3 = parseInt('-19', 10);
let n4 = parseInt('19 Grad', 10);
let n5 = parseInt('19.1', 10);
let n6 = parseInt('019', 10);
let n7 = parseInt(' 19', 10);
```

Besides the direct reading of integers with or without sign (n1, n2, n3), `parseInt` can also handle some more complex cases. Non-numeric characters after (n4, n5) as well as zeros (n6) and spaces (n7) before the integer will be ignored.  
  
In all examples, the second parameter passed to `parseInt` is `10`. This parameter specifies the radix (the base in mathematical numeral systems) on which the number is to be interpreted. `10` represents the usual decimal system. If you omit the second parameter, the decimal system is normally used as default. Since there are exceptions to this rule, you should always specify the radix!  
  
If `parseInt` cannot read an integer, it returns `NaN` (Not a Number).

```js
let n1 = parseInt('text', 10);
let n2 = parseInt('No. 10', 10);
```

In the first case there is no number at all. In the second case, there are non-numeric characters before the number. This is not allowed and results in `NaN`.

# Boolean

Another important data type next to String and Number is Boolean. It has only two possible values: `true` and `false`. You can calculate with Boolean values similar to numbers. JavaScript has three Boolean operators: `&&` (and), `||` (or) and `!` (not). `&&` links two Boolean values. If both values are `true`, the result is `true`. In all other cases it is `false`. With `||` the result is `true`, if at least one of the two input values is `true`. If both input values are `false`, the result is `false`. `!` is applied to a single Boolean value and inverts this value: `!true` is `false` and `!false` is `true`.

```js
let x1 = true && false;
let x2 = !x1;
let x3 = x1 || x2;
```

`x1` is `false`, `x2` is `true` and `x3` is `true`.

# Strict Equality

Two values can be checked for strict equality. The result of such a comparison is either `true`, the two values are equal, or `false`, the two values are not equal. The operator for strict equality is `===`.

```js
let language = 'JavaScript';
let x = 10;
let c1 = language === 'Java';
let c2 = x === 10;
let c3 = x === '10';
```

The first comparison results in `false`, because `language` does not have the value `'Java'`. So `c1` is `false`. The second comparison results in `true`, because the value of `x` equals `10`. So `c2` is `true`. In the case of strict equality, it is also important that the two compared values have the same data type. `c3` is `false`, because different data types are compared here. On the left side of the comparison is a number, on the right side a string.

# Strict Inequality

With `!==` two values are compared for strict inequality.

```js
let c1 = 'rose' !== 'Rose';
let c2 = 10 !== '10';
```

Both comparisons result in `true`. The first one, because the two strings differ in upper and lower case. The second, because the two values differ in type.

# Number Comparations

Numbers can be compared with the well-known mathematical symbols. In the following examples, all expressions return the value `true`.

```js
let v1 = 5 > 4;
let v2 = 5 >= 5;
let v3 = 5 < 6;
let v4 = 5 <= 5;
```

# if

Often code should only be executed if a certain condition is true. To do this, use the `if` statement.

```js
let win = 0;
if (dice === 6) {
  win = 100;
}
```

# Two Returns

With `if` you can write functions with two return statements:

```js
function prize(number) {
  if (number === 6) {
    return 100;
  }
  return 0;
}
```

If `number` has the value `6`, the `if` condition is fulfilled and the first `return` statement will be executed. The function terminates and returns `100`. If `number` does not have the value `6`, the `if` condition is not fulfilled. The code execution continues after the `if` block. The second return statement will be executed. The function terminates and returns `0`.  
  
However, be careful using two or more return statements in a function. Such code can become obscure.

# if ... else

If a code block should be executed if an `if` condition is not fulfilled, an `else` is added.

```js
let message;
if (amount > 1000) {
  message = 'No payout possible!';
} else {
  message = 'The amount will be paid out!';
}
```

Depending on whether `amount` is greater or smaller `1000`, either the `if` branch or the `else` branch is executed.

# else if

If you want to distinguish multiple cases, you can supplement an `if` with any number of `else if`. Finally, a single `else` can be added.

```js
let message;
if (amount > 1000) {
  message = 'Too high. No payout possible!';
} else if (amount < 10) {
  message = 'Too low. No payout possible!';
} else {
  message = 'The amount will be paid out!';
}
```

First it is checked whether `amount` is greater than `1000`. If so, the 'Too high ...' message is set and the code will be continued at the end of the entire block. If not, it is checked whether `amount` is less than `10`. If so, the 'Too low ...' message is set and the code will be continued at the end of the entire block. If no condition is met, the final `else` block is executed.

