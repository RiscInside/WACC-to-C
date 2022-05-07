## WACC-to-C

WACC-to-C is a transpiler from WACC programming language to GNU C. Possible applications include debugging WACC programs and using it to bootstrap a self-hosting WACC compiler.

WACC language is used for the compiler course at Imperial College London. Specification and examples are available at https://gitlab.doc.ic.ac.uk/rd3918/wacc_examples

### Features
* Semi-complete parser and semantic analysis engine (all tests passing)
* Typechecking with error recovery (try running tests/invalid/semanticErr/multiple/*)
* C code generation
* `extern` extension which allows to call external functions

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

### Building

Run `make`. That will compile transpiler's binary from a single source file `transpiler.c`. You will get two binaries:
* `transpiler-opt`: optimized transpiler, could be used for benchmarking
* `transpiler-dbg`: transpiler built in debug mode

### Running

Both binaries accept two command-line arguments: source path (has to end with `.wacc`) and output path. Output path is optional: if it is not specified, the transpiler will output directly to the `stdout`.

Script `run-on.sh` is provided for convinience. You can use it to run any `.wacc` file using `./transpiler-opt` and gcc.

### Testing

Run `make tests` to download tests from the specification repository. Run `make run-tests` to run all tests.

