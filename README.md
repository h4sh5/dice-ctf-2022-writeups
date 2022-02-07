# DiceCTF 2022 Writeups


Challenges done:



## rev flagle

https://flagle.mc.ax/

(saved here on archive https://web.archive.org/web/20220207114956/https://flagle.mc.ax/)

Opening up the browser network console when loading the site shows that there're a few files loaded:

<image src=rev_flagle/network.png>

script.js

flag-checker.js

flag-checker.wasm

The javascript function `submit_guess` (around line 111 of index.html) shows that the function `guess()` is called to check the input:
```js
const result = guess(i, guess_val);
```

But there's no guess() defined in the JS code. So maybe it's in the WASM (Web Assembly) file?

To decompile a wasm file and be able to analyze it nicely, we can use Ghidra and this plugin:

https://github.com/nneonneo/ghidra-wasm-plugin/

It needs to be installed - you can download the zip file w/ correct version from releases (corresponding to your version of Ghidra, if it's not there you will need to compile the plugin)

Once the file is loaded and analyzed in Ghidra, it should look like this: 

(find the guess function in the function list)


<image src=rev_flagle/ghidra_guess.png>

Note that the guess function from wasm is exported into the JS environment, since it's in the Exports list shown in Ghidra. The way it is called is `guess(i, guess_val)` in js, so we can assume `i` is the position of the flag piece and `guess_val` is the user input. 

We will rename those parameters in Ghidra correspondingly.

<image src=rev_flagle/rename_guess.png>

The return codes and what they mean are also defined in the index.html file, on line 68:

```js
    const CORRECT = 0;
    const WRONG_LOCATION = 1;
    const INCORRECT = 2;
```

At the buttom of the guess function we see `uVar1` is the return value. 

At various places of the code, `uVar1` is set to a condition e.g. `uVar1 = i != 2;`

That means if at that point of the code, the return value is the condition `i != 2`, which will return 0 (CORRECT) if `i == 2` and 1 (WRONG_LOCATION) otherwise.

Meaning, that `if` statement above it defines the conditions for the flag at index 2 (second piece).



```c
      if ((((guess_val[2] == '3') && (guess_val[3] == 'l')) && (guess_val[1] == '!')) &&
         ((guess_val[4] == 'D' && (*guess_val == 'F')))) {
        uVar1 = i != 2;
      }
```

That looks like a straight forward re-arranging:
guess_value[0] (`*guess_val`) is F, index [1] is '!', index [2] is '3', so on:

`F!3lD`

Using that same logic, we can get the flag at `i == 5`:

`m@x!M`

If all the 6 pieces make up the whole flag, it's probably safe to assume the first one is `dice{` follwoing the flag format:

<img src=rev_flagle/first3.png>

(it is also shown in line 14 of the decompiled code in Ghidra, where `streq(guess_val, 0x400)` means its comparing the string to the address at 0x400, which is `dice{` 

There we go! 3 down, 3 to go.

### Piece 3 and 6: SAT Solving

Flag pieces 3 and 6 are a bit more complicated:
```c
      else if (((guess_val[1] * *guess_val == 0x12c0) &&
               (iVar2 = guess_val[2], iVar2 + *guess_val == 0xb2)) &&
              ((iVar2 + guess_val[1] == 0x7e &&
               (((iVar3 = guess_val[3], iVar2 * iVar3 == 0x23a6 && (iVar3 - guess_val[4] == 0x3e))
                && (iVar2 * 0x12c0 - guess_val[4] * iVar3 == 0x59d5d)))))) {
        uVar1 = i != 3;
```

That's a lot of conditions, and it looks really gross.

But when it comes down to it, it's like an simultaneous equation with a lot of conditons. There are 5 variables, index 0-4 of the `guess_value`, and they need to satisfy certain conditions.

The first condition they need to satisfy is that, according to line 12 of the decompiled code (which we don't know what it is yet), the return value of `iVar2 = unnamed_function_10(guess_val);` has to be 5. 

That function takes our input and returns an integer, and it must be 5, and there are NULL byte comparisions in the code? Looks like `strlen()` to me. Let's just assume that the input has to be length 5 to be checked at all.

The other conditions can be written out manually, or, we can be smart about it and use a SAT solver to solve it. A popular one is [angr w/ Claripy](https://docs.angr.io/advanced-topics/claripy)


This is a nice article on how to use it to defeat code obfuscation: https://napongizero.github.io/blog/Defeating-Code-Obfuscation-with-Angr

So I copied out and re-compiled the if statement into a C binary (with 32 bit and `-no-pie` to make my life easier), writing it out like this:
```c
//gcc -m32 -no-pie ./index3.c -o index3
#include<stdio.h>
#include<stdlib.h>
int main () {
        char value[10];
        fgets(value, 10, stdin);
        value[5] = 0;
        char iVar1,iVar2;

        if (((value[1] * *value == 0x12c0) && (iVar1 = value[2], iVar1 + *value == 0xb2)) &&
              ((iVar1 + value[1] == 0x7e &&
               (((iVar2 = value[3], iVar1 * iVar2 == 0x23a6 && (iVar2 - value[4] == 0x3e)) &&
                (iVar1 * 0x12c0 - value[4] * iVar2 == 0x59d5d)))))) {
                puts("OK!");
        } else {
                puts("Nope!");
        }
}

```

Because I am printing "OK" when it wins, and I can find the location to avoid (which is when the binary calles `puts` the second time), I can setup angr to basically fire-and-forget:
```py
# try until SUCCESS is printed
target = lambda s: b"OK" in s.posix.dumps(1) 

# not much to avoid
avoid = [0x080492e7]

# specify state in the manager
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=target,avoid=avoid)
```

The addresses for main etc. are found by running the binary in gdb or objdump and copying out the exact 32 bit address.

See the full script [here](rev_flagle/brute3.py) and C code [here](rev_flagle/index3.c)

(Make sure you install angr in your system / virtual env using `pip` of course)

and we just run the python script, which loads the binary and automagically find the flag for us:
```
$ python3 brute3.py
...
found! : <SimState @ 0x80492d8>
b'd0Nu7\n'
```


Now that we got 3, we can do 6 the exact same way:

```c
//gcc -m32 -no-pie ./index6.c -o index6
#include<stdio.h>
#include<stdlib.h>
int main () {
        char value[10];
        fgets(value, 10, stdin);
        value[5] = 0;
        // char iVar1,iVar2;

        if ((((value[1] + 0xb75) * (*value + 0x6e3) == 0x53acdf) && (value[4] == '}')) &&
                 ((value[3] + 0x60a) * (value[2] + 0xf49) == 0x62218f)) {
                puts("OK!");
        } else {
                puts("Nope!");
        }
}
```
See the full script [here](rev_flagle/brute6.py)

```
$ python3 brute6.py
...
found! : <SimState @ 0x804927d>
b'T$r3}\n'
```

<img src=rev_flagle/flag3_6.png>

Ok, last piece!

### Piece 4 - pain

Ok, so `i != 4` is not found in the wasm guess function. It's found in [flag-checker.js](rev_flagle/flag-checker.js) on line 1729:
```js
function validate_4(a){ return c(UTF8ToString(a)) == 0 ? 0 : 1; }
```

Which calls `c`, this really obfuscated function in [script.js](rev_flagle/script.js):

```js
function c(b){var e={'HLPDd':function(g,h){return g===h;},'tIDVT':function(g,h){return g(h);},'QIMdf':function(g,h){return g-h;},'FIzyt':'int','oRXGA':function(g,h){return g<<h;},'AMINk':function(g,h){return g&h;}},f=current_guess;try{let g=e['HLPDd'](btoa(e['tIDVT'](intArrayToString,window[b](b[e['QIMdf'](f,0x26f4+0x1014+-0x3707*0x1)],e['FIzyt'])()['toString'](e['oRXGA'](e['AMINk'](f,-0x1a3*-0x15+0x82e*-0x1+-0x1a2d),0x124d+-0x1aca+0x87f))['match'](/.{2}/g)['map'](h=>parseInt(h,f*f)))),'ZGljZQ==')?-0x1*0x1d45+0x2110+-0x3ca:-0x9*0x295+-0x15*-0x3+0x36*0x6d;}catch{return 0x1b3c+-0xc9*0x2f+-0x19*-0x63;}}
```

suuuper gross. 

After an intense period of prettifying and deobfucation and renaming, it looks like this:
```js

// specifically made for logging
function testParseint(x,y) {
    console.log('parseInt:',x,y);
    return parseInt(x,y);
}


function c(b)
{
    var e = {
            'equals': function(g, h)
            {
                console.log('equals:', g, h);
                return g === h;
            },
            'funcCall': function(g, h)
            {
                console.log('funccall:', g, h);
                return g(h);
            },
            'minus': function(g, h)
            {
                console.log('minus:', g, h);
                return g - h;
            },
            'FIzyt': 'int',
            '<<shift': function(g, h)
            {
                console.log('shift:', g, h);
                return g << h;
            },
            '&and': function(g, h)
            {
                console.log('&and:', g, h);
                return g & h;
            }
        },
        f = current_guess;
    try
    {
        console.log(window);
        let g = e['equals'](
                btoa(
                    e['funcCall'](intArrayToString, window[b](b[e['minus'](f, 1)], 'int')()['toString'](e['<<shift'](e['&and'](f, 4), 2)) ['match'](/.{2}/g)['map'](h => testParseint(h, f * f))
                )), //<- g

             'ZGljZQ==') ? 1 : 0; // <- h
        return g;
        //ZGljZQ== is 'dice'

    }
    catch (e)
    {   console.log('error:',e)
        return 0; // 0
    }
}


```

So looks like it's doing an operation to each pair of chars in the input (pairs because of the regex `/.{2}/g`, which you can test on https://regex101.com)

The operation is similar to a hex decode when `f*f = 16` (when f is 4), because the `parseInt` function in js converts a string to an integer of a base given by the argument.

I made the rewrite function above, and I could see what was happening by pasting it into the console and then entering input, because the `testParseint` function I wrote gives me some logging.

The trick to solving this is the `window[b]`, where `b` is maybe our input. The special thing about `window` is that it's the global window context object, which only has that many keys. We know that this function `c()` returns 0 when it fails, so we can brute force all the 5-length keys in `window`, but **only when f=4, meaning current_guess=4** (`f = current_guess`  in the code), because:
1. we are missing the 4th part of the flag (assumption) and
2. it doesn't make sense to decode in any other base (1,4,9,25 or 36??)

so this loop in the console would solve it:
```js
current_guess=4; 
for (k in window) {
	if (k.length==5) {
		if (c(k) !== 0) {
			console.log('win:', k);
		}
	}
}
```

win: `cwrap`

would only work when current_guess=4, so on the GUI it looks like this to get it:

<img src=rev_flagle/cwrap.png>

(only works on 4th grid)

There we go!


<img src=rev_flagle/flag.png>




