## WACC-to-C

WACC-to-C is a transpiler from WACC programming language to GNU C. Possible applications include debugging WACC programs and using it to bootstrap a self-hosting WACC compiler.

WACC language is used for the compiler course at Imperial College London. Specification and examples are available at https://gitlab.doc.ic.ac.uk/lab2122_spring/wacc_examples/-/raw/master/WACCLangSpec.pdf?inline=false

### Features
* Semi-complete parser and semantic analysis engine (all tests passing)
* Typechecking with error recovery (try running tests/invalid/semanticErr/multiple/*)
* C code generation
* `extern` extension which allows to call external functions
* Pairs extensions
* Boehm–Demers–Weiser garbage collector support

### `extern` extension

WACC language is extended with a new construct: `extern`. Language grammar is changed as follows:

```
<program> ::= <begin> <toplvldecl>* <stat> <end>
<toplvldecl> ::= <func> | <extern>
<extern> ::= "extern" <type> <ident> <param-list>
```

For example, you can use extern to implement cat
```ada
begin
    extern int getchar()
    extern int putchar(int c)

    int EOF = -1;
    int c = call getchar();
    while c != EOF do
        int _ = call putchar(c);
        c = call getchar()
    done
end
```

### Pairs extension

Pair types have been extended so that they are a bit less clumsy. `pair` (aka opaque pair type) is now a valid type on its own. Additionally, non-opaque pairs can be nested to preserve type information.

### Building

Run `make`. That will compile transpiler's binary from a single source file `transpiler.c`. You will get two binaries:
* `transpiler-opt`: optimized transpiler, could be used for benchmarking
* `transpiler-dbg`: transpiler built in debug mode

### Running

Both binaries accept two command-line arguments: source path (has to end with `.wacc`) and output path. Output path is optional: if it is not specified, the transpiler will output directly to the `stdout`.

Script `run-on.sh` is provided for convinience. You can use it to run any `.wacc` file using `./transpiler-opt` and gcc.

### Testing

Run `make tests` to download tests from the specification repository. Run `make run-tests` to run all tests.

### Debugging WACC programs

You can debug WACC programs with `CGEN_LINE_CONTROL` environment variable. This environemnt variable instructs the compiler to emit line control directives. See `run-on-gdb.sh` script for how this can be used.

```
Breakpoint 1, main () at tests/valid/advanced/ticTacToe.wacc:1055
1055
(gdb) n
1056            char playerSymbol = call chooseSymbol() ;
(gdb) n
========= Tic Tac Toe ================
=  Because we know you want to win   =
======================================
=                                    =
= Who would you like to be?          =
=   x  (play first)                  =
=   o  (play second)                 =
=   q  (quit)                        =
=                                    =
======================================
Which symbol you would like to choose: x
You have chosen: x
1057            char aiSymbol = call oppositeSymbol(playerSymbol) ;
(gdb) n
1058            char currentTurn = 'x' ;
(gdb) n
1060            pair(pair, pair) board = call allocateNewBoard() ;
(gdb) n
1062            println "Initialising AI. Please wait, this may take a few minutes." ;
(gdb) n
Initialising AI. Please wait, this may take a few minutes.
1063            pair(pair, pair) aiData = call initAI(aiSymbol) ;
(gdb) n
1065            int turnCount = 0 ;
(gdb) n
1066            char winner = '\0' ;
(gdb) n
1068            bool _ = call printBoard(board) ;
(gdb) n
 1 2 3
1 | | 
 -+-+-
2 | | 
 -+-+-
3 | | 

1070            while winner == '\0' && turnCount < 9 do
(gdb) n
1071                    int[] move = [0, 0] ;
(gdb) n
1072                    _ = call askForAMove(board, currentTurn, playerSymbol, aiData, move) ;
(gdb) p winner
$1 = 0 '\000'
(gdb) p turnCount
$2 = 0
(gdb) p move
$3 = (ArrayOfInt) 0x555568374e88
```

#### Function names

Transpiler mangles C function names by prepending `$` to all of them. This means that you have to manually prepend `$` to all function names.

```
(gdb) b $askForAMove
Breakpoint 2 at 0x555555556a4d: file tests/valid/advanced/ticTacToe.wacc, line 788.
```

### Boehm–Demers–Weiser garbage collector GC support

Managing memory for all heap-allocated pairs is rather annoying. Thankfully, there is a way to make WACC a managed language.

Setting `CGEN_BOEHM` environment variable makes the transpiler call into Boehm GC library for all `malloc()`/`free()` calls.

Use `run-on-gc.sh` script to test programs with Boehm GC enabled.
