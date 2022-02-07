# DiceCTF 2022 Writeups


Challenges done:



## rev flagle

https://flagle.mc.ax/

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

`M@x!m`

