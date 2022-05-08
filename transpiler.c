#include <alloca.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <search.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define WACC_EXTENSION ".wacc"
#define C_EXTENSION ".c"
#define VALID_ESCAPES "0btnfr\"\'\\"

#define EXIT_SEMANTIC_ERROR 200
#define EXIT_SYNTAX_ERROR 100
#define EXIT_MISC_ERROR -1

const char *source_path;
const char *source;
size_t source_size;
size_t source_pos = 0;

// 1 TB
#define ETERNAL_POOL_SIZE 1099511627776

void *alloc_eternal(size_t size, size_t align) {
  static void *current = NULL;
  static size_t offset = 0;
  if (current == NULL) {
    current = mmap(NULL, ETERNAL_POOL_SIZE, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (current == MAP_FAILED) {
      perror("internal error: failed to map eternal memory pool");
      exit(EXIT_MISC_ERROR);
    }
  }
  offset = ((offset + align - 1) / align) * align;
  void *res = (void *)((uintptr_t)current + offset);
  offset += size;
  return res;
}

struct pos {
  size_t line;
  size_t column;
};

void to_pos(size_t raw, struct pos *buf) {
  static size_t newlines = 0;
  static size_t last_newline = 0;
  static size_t cur = 0;
  if (cur > raw) {
    cur = 0;
    newlines = 0;
    last_newline = 0;
  }

  for (; cur < raw; ++cur) {
    if (source[cur] == '\n') {
      last_newline = cur;
      newlines++;
    }
  }
  buf->line = newlines + 1;
  buf->column = raw - last_newline;
}

struct tok {
  const char *tok_start;
  int tok_size;
  enum {
    TOK_BEGIN,
    TOK_END,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_IS,
    TOK_COMMA,
    TOK_SEMICOLON,
    TOK_SKIP,
    TOK_ASSIGN,
    TOK_PRINT,
    TOK_PRINTLN,
    TOK_READ,
    TOK_FREE,
    TOK_RETURN,
    TOK_EXIT,
    TOK_IF,
    TOK_THEN,
    TOK_ELSE,
    TOK_FI,
    TOK_WHILE,
    TOK_DO,
    TOK_DONE,
    TOK_NEWPAIR,
    TOK_CALL,
    TOK_FST,
    TOK_SND,
    TOK_INT,
    TOK_BOOL,
    TOK_CHAR,
    TOK_STRING,
    TOK_LBRACKET,
    TOK_RBRACKET,
    TOK_PAIR,
    TOK_EXCLAMATION_MARK,
    TOK_DASH,
    TOK_LEN,
    TOK_ORD,
    TOK_CHR,
    TOK_ASTERIX,
    TOK_SLASH,
    TOK_PERCENT_SIGN,
    TOK_PLUS_SIGN,
    TOK_GT_SIGN,
    TOK_GE_SIGN,
    TOK_LT_SIGN,
    TOK_LE_SIGN,
    TOK_EQ_SIGN,
    TOK_NE_SIGN,
    TOK_AND,
    TOK_OR,
    TOK_IDENT,
    TOK_INT_LITERAL,
    TOK_BOOL_LITERAL,
    TOK_CHAR_LITERAL,
    TOK_STRING_LITERAL,
    TOK_NULL,
    TOK_EXTERN
  } tok_kind;
};

void tok_skip_to_non_whitespace() {
  while (source_pos < source_size) {
    if (isspace(source[source_pos])) {
      source_pos++;
      continue;
    } else if (source[source_pos] == '#') {
      source_pos++;
      while (source_pos < source_size && source[source_pos] != '\n') {
        source_pos++;
      }
    } else {
      break;
    }
  }
}

void tok_fill(struct tok *buf, int tok_kind, size_t len) {
  buf->tok_kind = tok_kind;
  buf->tok_size = len;
  buf->tok_start = source + source_pos;
}

void tok_fill_singleton(struct tok *buf, int tok_kind) {
  tok_fill(buf, tok_kind, 1);
}

bool tok_peek_kernel(struct tok *buf) {
  tok_skip_to_non_whitespace();
  if (source_pos == source_size) {
    return false;
  }

  size_t remaining = source_size - source_pos;

#define TOK_SINGLETON_CASE(c, kind)                                            \
  case c: {                                                                    \
    tok_fill_singleton(buf, kind);                                             \
    return true;                                                               \
  }

#define TOK_MATCHES(_str)                                                      \
  (strlen(_str) <= remaining &&                                                \
   memcmp(source + source_pos, _str, strlen(_str)) == 0)

  switch (source[source_pos]) {
    TOK_SINGLETON_CASE('-', TOK_DASH);
    TOK_SINGLETON_CASE('*', TOK_ASTERIX);
    TOK_SINGLETON_CASE('/', TOK_SLASH);
    TOK_SINGLETON_CASE('%', TOK_PERCENT_SIGN);
    TOK_SINGLETON_CASE('+', TOK_PLUS_SIGN);
    TOK_SINGLETON_CASE('(', TOK_LPAREN);
    TOK_SINGLETON_CASE(')', TOK_RPAREN);
    TOK_SINGLETON_CASE(',', TOK_COMMA);
    TOK_SINGLETON_CASE('[', TOK_LBRACKET);
    TOK_SINGLETON_CASE(']', TOK_RBRACKET);
    TOK_SINGLETON_CASE(';', TOK_SEMICOLON);

  default: {
    if (isdigit(source[source_pos])) {
      size_t cur = source_pos;
      while (cur < source_size) {
        if (!isdigit(source[cur])) {
          break;
        }
        cur++;
      }
      tok_fill(buf, TOK_INT_LITERAL, cur - source_pos);
      return true;

    } else if (source[source_pos] == '\"') {
      size_t cur = source_pos + 1;
      bool escaped = false;
      while (cur < source_size) {
        if (escaped && strchr(VALID_ESCAPES, source[cur]) == NULL) {
          struct pos pos;
          to_pos(cur, &pos);
          fprintf(stderr, "error at %s:%zu:%zu: invalid escape char \'%c\'\n",
                  source_path, pos.line, pos.column, source[cur]);
          exit(EXIT_SYNTAX_ERROR);
        } else if (escaped) {
          escaped = false;
        } else if (!escaped && source[cur] == '\\') {
          escaped = true;
        } else if (!escaped && source[cur] == '\"') {
          tok_fill(buf, TOK_STRING_LITERAL, cur + 1 - source_pos);
          return true;
        }
        cur++;
      }
      struct pos pos;
      to_pos(cur, &pos);
      fprintf(
          stderr,
          "error at %s:%zu:%zu: unexpected EOF while parsing string token\n",
          source_path, pos.line, pos.column);
      exit(EXIT_SYNTAX_ERROR);

    } else if (source[source_pos] == '\'') {
      char first_char = source[source_pos + 1];
      size_t length = first_char == '\\' ? 4 : 3;
      if (first_char == '\'') {
        struct pos pos;
        to_pos(source_pos, &pos);
        fprintf(stderr, "error at %s:%zu:%zu: empty character constant\n",
                source_path, pos.line, pos.column);
        exit(EXIT_SYNTAX_ERROR);
      } else if (source_pos + length >= source_size) {
        struct pos pos;
        to_pos(source_size, &pos);
        fprintf(stderr,
                "error at %s:%zu:%zu: unexpected EOF while parsing character "
                "constant\n",
                source_path, pos.line, pos.column);
        exit(EXIT_SYNTAX_ERROR);
      } else if (first_char == '\\') {
        char escaped_char = source[source_pos + 2];
        if (strchr(VALID_ESCAPES, escaped_char) == 0) {
          struct pos pos;
          to_pos(source_pos + 2, &pos);
          fprintf(stderr, "error at %s:%zu:%zu: invalid escape char \'%c\'\n",
                  source_path, pos.line, pos.column, escaped_char);
          exit(EXIT_SYNTAX_ERROR);
        }
      } else if (first_char == '\"') {
        struct pos pos;
        to_pos(source_pos + 1, &pos);
        fprintf(stderr,
                "error at %s:%zu:%zu: unescaped character constant \'%c\'\n",
                source_path, pos.line, pos.column, first_char);
        exit(EXIT_SYNTAX_ERROR);
      }
      tok_fill(buf, TOK_CHAR_LITERAL, length);
      return true;
    } else if (TOK_MATCHES(">=")) {
      tok_fill(buf, TOK_GE_SIGN, strlen(">="));
      return true;
    } else if (TOK_MATCHES("<=")) {
      tok_fill(buf, TOK_LE_SIGN, strlen("<="));
      return true;
    } else if (TOK_MATCHES(">")) {
      tok_fill(buf, TOK_GT_SIGN, strlen(">"));
      return true;
    } else if (TOK_MATCHES("<")) {
      tok_fill(buf, TOK_LT_SIGN, strlen("<"));
      return true;
    } else if (TOK_MATCHES("!=")) {
      tok_fill(buf, TOK_NE_SIGN, strlen("!="));
      return true;
    } else if (TOK_MATCHES("==")) {
      tok_fill(buf, TOK_EQ_SIGN, strlen("=="));
      return true;
    } else if (TOK_MATCHES("=")) {
      tok_fill(buf, TOK_ASSIGN, strlen("="));
      return true;
    } else if (TOK_MATCHES("!")) {
      tok_fill(buf, TOK_EXCLAMATION_MARK, strlen("!"));
      return true;
    } else if (TOK_MATCHES("&&")) {
      tok_fill(buf, TOK_AND, strlen("&&"));
      return true;
    } else if (TOK_MATCHES("||")) {
      tok_fill(buf, TOK_OR, strlen("||"));
      return true;
    } else if (isalpha(source[source_pos]) || source[source_pos] == '_') {
#define TOK_HANDLE_KEYWORD(_type, _keyword)                                    \
  if (strlen(_keyword) == cur - source_pos &&                                  \
      memcmp(source + source_pos, _keyword, cur - source_pos) == 0) {          \
    tok_fill(buf, _type, cur - source_pos);                                    \
    return true;                                                               \
  }
      size_t cur = source_pos;
      while (cur < source_size) {
        if (!(isalnum(source[cur]) || source[cur] == '_')) {
          break;
        }
        cur++;
      }

      switch (source[source_pos]) {
      case 'b':
        TOK_HANDLE_KEYWORD(TOK_BEGIN, "begin")
        TOK_HANDLE_KEYWORD(TOK_BOOL, "bool")
        break;
      case 'c':
        TOK_HANDLE_KEYWORD(TOK_CALL, "call")
        TOK_HANDLE_KEYWORD(TOK_CHAR, "char")
        TOK_HANDLE_KEYWORD(TOK_CHR, "chr")
        break;
      case 'd':
        TOK_HANDLE_KEYWORD(TOK_DONE, "done")
        TOK_HANDLE_KEYWORD(TOK_DO, "do")
        break;
      case 'e':
        TOK_HANDLE_KEYWORD(TOK_END, "end")
        TOK_HANDLE_KEYWORD(TOK_EXIT, "exit")
        TOK_HANDLE_KEYWORD(TOK_ELSE, "else")
        TOK_HANDLE_KEYWORD(TOK_EXTERN, "extern")
        break;
      case 'f':
        TOK_HANDLE_KEYWORD(TOK_BOOL_LITERAL, "false")
        TOK_HANDLE_KEYWORD(TOK_FI, "fi")
        TOK_HANDLE_KEYWORD(TOK_FREE, "free")
        TOK_HANDLE_KEYWORD(TOK_FST, "fst")
        break;
      case 'i':
        TOK_HANDLE_KEYWORD(TOK_IS, "is")
        TOK_HANDLE_KEYWORD(TOK_IF, "if")
        TOK_HANDLE_KEYWORD(TOK_INT, "int")
        break;
      case 'l':
        TOK_HANDLE_KEYWORD(TOK_LEN, "len")
        break;
      case 'n':
        TOK_HANDLE_KEYWORD(TOK_NEWPAIR, "newpair")
        TOK_HANDLE_KEYWORD(TOK_NULL, "null")
        break;
      case 'o':
        TOK_HANDLE_KEYWORD(TOK_ORD, "ord")
        break;
      case 'p':
        TOK_HANDLE_KEYWORD(TOK_PAIR, "pair")
        TOK_HANDLE_KEYWORD(TOK_PRINTLN, "println")
        TOK_HANDLE_KEYWORD(TOK_PRINT, "print")
        break;
      case 'r':
        TOK_HANDLE_KEYWORD(TOK_READ, "read")
        TOK_HANDLE_KEYWORD(TOK_RETURN, "return")
        break;
      case 's':
        TOK_HANDLE_KEYWORD(TOK_SKIP, "skip")
        TOK_HANDLE_KEYWORD(TOK_SND, "snd")
        TOK_HANDLE_KEYWORD(TOK_STRING, "string")
        break;
      case 't':
        TOK_HANDLE_KEYWORD(TOK_THEN, "then")
        TOK_HANDLE_KEYWORD(TOK_BOOL_LITERAL, "true")
        break;
      case 'w':
        TOK_HANDLE_KEYWORD(TOK_WHILE, "while")
        break;
      default:
        break;
      }

      tok_fill(buf, TOK_IDENT, cur - source_pos);
      return true;
    }
  }
  }
  struct pos pos;
  to_pos(source_pos, &pos);
  fprintf(stderr, "error at %s:%zu:%zu: unrecognized token\n", source_path,
          pos.line, pos.column);
  exit(EXIT_SYNTAX_ERROR);
}

struct tok saved_token = {NULL, 0, 0};

bool tok_saved_valid() {
  if (saved_token.tok_start == NULL) {
    return false;
  }
  return (size_t)(saved_token.tok_start - source) == source_pos;
}

bool tok_peek_token(struct tok *buf) {
  if (!tok_saved_valid()) {
    if (tok_peek_kernel(&saved_token)) {
      *buf = saved_token;
      return true;
    }
    return false;
  }
  *buf = saved_token;
  return true;
}

bool tok_poll_token(struct tok *buf) {
  bool res = tok_peek_token(buf);
  if (res) {
    source_pos += buf->tok_size;
  }
  return res;
}

void tok_peek_token_no_eof(struct tok *buf, const char *expected_token_string) {
  struct pos pos;
  if (!tok_peek_token(buf)) {
    to_pos(source_size, &pos);
    fprintf(stderr, "error at %s:%zu:%zu: unexpected EOF (expected %s)\n",
            source_path, pos.line, pos.column, expected_token_string);
    exit(EXIT_SYNTAX_ERROR);
  }
}

void tok_poll_token_no_eof(struct tok *buf, const char *expected_token_string) {
  tok_peek_token_no_eof(buf, expected_token_string);
  source_pos += buf->tok_size;
}

void tok_report_unexpected(struct tok *buf, const char *expected_token_string) {
  struct pos pos;
  to_pos(buf->tok_start - source, &pos);
  fprintf(stderr,
          "error at %s:%zu:%zu: unexpected token (expected %s, got \'%.*s\')\n",
          source_path, pos.line, pos.column, expected_token_string,
          buf->tok_size, buf->tok_start);
  exit(EXIT_SYNTAX_ERROR);
}

void tok_extract_of_type(struct tok *tok, int kind,
                         const char *expected_token_string) {
  tok_poll_token_no_eof(tok, expected_token_string);
  if ((int)tok->tok_kind != kind) {
    tok_report_unexpected(tok, expected_token_string);
  }
}

void tok_expect_token(int kind, const char *expected_token_string) {
  struct tok tok;
  tok_extract_of_type(&tok, kind, expected_token_string);
}

typedef uint32_t tindex_t;

#define TINDEX_INVALID ((tindex_t)-1)

struct ast_node {
  const char *string_data;
  int string_data_len;
  int next_child;
  int first_child;
  enum {
    AST_NODE_PROGRAM,        // <no tag> function* statement
    AST_NODE_FUNC,           // <no tag> type name param_list scope
    AST_NODE_EXTERN,         // <no tag> type name param_list
    AST_NODE_IDENT,          // <id string> [no children]
    AST_NODE_PARAM_LIST,     // <no tag> param*
    AST_NODE_PARAM,          // <no tag> type name
    AST_NODE_DECL,           // <no tag> type name assign-rhs
    AST_NODE_ASSIGNMENT,     // <no tag> assign-lhs assign-rhs
    AST_NODE_SKIP,           // <skip>
    AST_NODE_RETURN,         // <return> expr
    AST_NODE_RT_CALL,        // <free|exit|print|println> expr
    AST_NODE_RT_READ,        // <read> assign-lhs
    AST_NODE_IF,             // <if> expr scope scope
    AST_NODE_WHILE,          // <while> expr scope
    AST_NODE_SCOPE,          // <no tag> stmt*
    AST_NODE_ARRAY_ELEM,     // <no tag> ident expr* (subscripts)
    AST_NODE_PAIR_ELEM,      // <fst|snd> expr
    AST_NODE_ARRAY_LITERAL,  // <no tag> expr*
    AST_NODE_RT_NEWPAIR,     // <no tag> expr expr
    AST_NODE_CALL,           // <function name> expr*
    AST_NODE_PRIMITIVE_TYPE, // <int|bool|char|string|pair>
    AST_NODE_ARRAY,          // non-array type
    AST_NODE_PAIR,           // <no tag> type type (not a pair in both cases)
    AST_NODE_INT_LITERAL,    // <int literal> [no children]
    AST_NODE_BOOL_LITERAL,   // <bool literal> [no children]
    AST_NODE_CHAR_LITERAL,   // <char literal> [no children]
    AST_NODE_STRING_LITERAL, // <string literal> [no children]
    AST_NODE_NULL_LITERAL,   // <"null"> [no children]
    AST_NODE_UNARY,          // <unary operator used> expr
    AST_NODE_BINARY,         // <binary operator used> expr
  } kind;
  int token_id;    // set for operators
  tindex_t tindex; // set for expressions
};

#define AST_NODES_MAX 16777216

struct ast_node *ast_nodes;

struct ast_node *ast_first_child(struct ast_node *cur) {
  if (cur->first_child == -1) {
    return NULL;
  }
  return ast_nodes + cur->first_child;
}

struct ast_node *ast_next_child(struct ast_node *cur) {
  if (cur->next_child == -1) {
    return NULL;
  }
  return ast_nodes + cur->next_child;
}

struct ast_node *ast_nth_child(struct ast_node *cur, int n) {
  cur = ast_first_child(cur);
  for (int i = 0; i < n; ++i) {
    cur = ast_next_child(cur);
  }
  return cur;
}

struct ast_node *ast_last_child(struct ast_node *cur) {
  cur = ast_first_child(cur);
  while (cur != NULL) {
    struct ast_node *next = ast_next_child(cur);
    if (next == NULL) {
      return cur;
    }
    cur = next;
  }
  return NULL;
}

size_t ast_count_children(struct ast_node *cur) {
  size_t res = 0;
  cur = ast_first_child(cur);
  while (cur != NULL) {
    res++;
    cur = ast_next_child(cur);
  }
  return res;
}

void ast_add_first_child(struct ast_node *cur, struct ast_node *child) {
  cur->first_child = child - ast_nodes;
}

void ast_add_next_child(struct ast_node *last_child,
                        struct ast_node *new_child) {
  last_child->next_child = new_child - ast_nodes;
}

void ast_add_child(struct ast_node *cur, struct ast_node *child,
                   struct ast_node **cur_child_r) {
  if (*cur_child_r == NULL) {
    ast_add_first_child(cur, child);
  } else {
    ast_add_next_child(*cur_child_r, child);
  }
  *cur_child_r = child;
}

void ast_set_tag(struct ast_node *node, const char *tag, int tag_size) {
  node->string_data = tag;
  node->string_data_len = tag_size;
}

struct ast_node *ast_alloc_node(int kind) {
  static int ast_last_allocated = 0;
  int idx = ast_last_allocated++;
  if (idx == AST_NODES_MAX) {
    fprintf(stderr, "internal error: failed to allocate ast node from pool\n");
    exit(EXIT_SYNTAX_ERROR);
  }
  struct ast_node *res = ast_nodes + idx;
  res->kind = kind;
  res->first_child = -1;
  res->next_child = -1;
  res->string_data = NULL;
  res->string_data_len = 0;
  res->token_id = -1;
  res->tindex = TINDEX_INVALID;
  return res;
}

struct ast_node *ast_alloc_node_tok(int kind, struct tok *tok) {
  struct ast_node *res = ast_alloc_node(kind);
  res->string_data = tok->tok_start;
  res->string_data_len = tok->tok_size;
  return res;
}

void frepeat(FILE *f, const char *str, int times) {
  for (int i = 0; i < times; ++i) {
    fputs(str, f);
  }
}

struct ast_node *parse_type();

struct ast_node *parse_pair_type_component() {
  struct tok tok;
  tok_peek_token_no_eof(&tok, "pair type component");
  if (tok.tok_kind == TOK_PAIR) {
    tok_poll_token(&tok);
    struct ast_node *ptr = ast_alloc_node(AST_NODE_PRIMITIVE_TYPE);
    ast_set_tag(ptr, tok.tok_start, tok.tok_size);
    ptr->token_id = tok.tok_kind;
    return ptr;
  }
  return parse_type();
}

struct ast_node *parse_non_array_type() {
  struct tok tok;
  tok_poll_token_no_eof(&tok, "type");

  struct ast_node *res;

  switch (tok.tok_kind) {
  case TOK_INT:
  case TOK_BOOL:
  case TOK_STRING:
  case TOK_CHAR:
    res = ast_alloc_node_tok(AST_NODE_PRIMITIVE_TYPE, &tok);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    res->token_id = tok.tok_kind;
    break;
  case TOK_PAIR: {
    res = ast_alloc_node(AST_NODE_PAIR);
    const char *start = tok.tok_start;
    struct ast_node *last_child = NULL;

    tok_expect_token(TOK_LPAREN, "\'(\'");
    ast_add_child(res, parse_pair_type_component(), &last_child);
    tok_expect_token(TOK_COMMA, "\',\'");
    ast_add_child(res, parse_pair_type_component(), &last_child);
    tok_extract_of_type(&tok, TOK_RPAREN, "\')\'");

    ast_set_tag(res, start, tok.tok_start + tok.tok_size - start);
    break;
  }
  default:
    tok_report_unexpected(&tok, "type");
  }

  return res;
}

struct ast_node *parse_type() {
  struct ast_node *res = parse_non_array_type();
  while (true) {
    struct tok tok;
    if (!tok_peek_token(&tok) || tok.tok_kind != TOK_LBRACKET) {
      break;
    }
    tok_poll_token(&tok);
    struct ast_node *arr = ast_alloc_node(AST_NODE_ARRAY);
    tok_extract_of_type(&tok, TOK_RBRACKET, "\']\'");
    ast_set_tag(arr, res->string_data,
                tok.tok_start + tok.tok_size - res->string_data);
    ast_add_first_child(arr, res);
    res = arr;
  }
  return res;
}

struct ast_node *parse_ident() {
  struct tok tok;
  tok_extract_of_type(&tok, TOK_IDENT, "identifier");
  struct ast_node *res = ast_alloc_node(AST_NODE_IDENT);
  ast_set_tag(res, tok.tok_start, tok.tok_size);
  return res;
}

bool parse_on_type() {
  struct tok tok;
  if (!tok_peek_token(&tok)) {
    return false;
  }

  return tok.tok_kind == TOK_STRING || tok.tok_kind == TOK_CHAR ||
         tok.tok_kind == TOK_INT || tok.tok_kind == TOK_BOOL ||
         tok.tok_kind == TOK_PAIR;
}

bool parse_on_extern() {
  struct tok tok;
  if (!tok_peek_token(&tok)) {
    return false;
  }

  return tok.tok_kind == TOK_EXTERN;
}

struct ast_node *parse_expr();

struct ast_node *parse_array_elem_or_ident() {
  struct ast_node *ident = parse_ident();
  struct ast_node *node = ident;
  struct ast_node *last_child = NULL;
  while (true) {
    struct tok tok;
    if (!tok_peek_token(&tok) || tok.tok_kind != TOK_LBRACKET) {
      return node;
    } else if (node == ident) {
      node = ast_alloc_node(AST_NODE_ARRAY_ELEM);
      ast_set_tag(node, ident->string_data, ident->string_data_len);
      ast_add_child(node, ident, &last_child);
    }
    tok_poll_token(&tok);
    struct ast_node *expr = parse_expr();
    ast_add_child(node, expr, &last_child);
    tok_expect_token(TOK_RBRACKET, "\']\'");
  }
  return node;
}

struct ast_node *parse_expr0() {
  struct tok tok;
  struct ast_node *res;
  tok_peek_token_no_eof(&tok, "primary expression");

  switch (tok.tok_kind) {
  case TOK_BOOL_LITERAL:
    tok_poll_token(&tok);
    res = ast_alloc_node(AST_NODE_BOOL_LITERAL);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    break;
  case TOK_DASH:
  case TOK_PLUS_SIGN: {
    tok_poll_token(&tok);
    struct tok tok2;
    tok_peek_token_no_eof(&tok2, "primary expression");
    if (tok2.tok_kind != TOK_INT_LITERAL) {
      if (tok.tok_kind == TOK_PLUS_SIGN) {
        tok_report_unexpected(&tok2, "integer");
      } else {
        res = ast_alloc_node(AST_NODE_UNARY);
        res->token_id = tok.tok_kind;
        struct ast_node *child = parse_expr0();
        ast_set_tag(res, tok.tok_start,
                    child->string_data + child->string_data_len -
                        tok.tok_start);
        ast_add_first_child(res, child);
        break;
      }
    }
  }
  // fallthrough
  case TOK_INT_LITERAL: {
    tok_poll_token(&tok);
    char prev = tok.tok_start == source ? '\0' : *(tok.tok_start - 1);
    bool negate_integer_literal = prev == '-';
    bool extend_integer_literal = prev == '-' || prev == '+';
    res = ast_alloc_node(AST_NODE_INT_LITERAL);
    if (extend_integer_literal) {
      ast_set_tag(res, tok.tok_start - 1, tok.tok_size + 1);
    } else {
      ast_set_tag(res, tok.tok_start, tok.tok_size);
    }
    // should be safe, since after the token there could only be a null
    // character or some non-numeric character
    long value = strtol(tok.tok_start, NULL, 10);
    if (value > ((long)INT_MAX + 1) ||
        (value > INT_MAX && !negate_integer_literal)) {
      struct pos pos;
      to_pos(tok.tok_start - source, &pos);
      fprintf(stderr,
              "error at %s:%zu:%zu: integer constant \'%.*s\' outside of the "
              "valid range\n",
              source_path, pos.line, pos.column, tok.tok_size, tok.tok_start);
      exit(EXIT_SYNTAX_ERROR);
    }
  } break;
  case TOK_CHAR_LITERAL:
    tok_poll_token(&tok);
    res = ast_alloc_node(AST_NODE_CHAR_LITERAL);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    break;
  case TOK_STRING_LITERAL:
    tok_poll_token(&tok);
    res = ast_alloc_node(AST_NODE_STRING_LITERAL);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    break;
  case TOK_NULL:
    tok_poll_token(&tok);
    res = ast_alloc_node(AST_NODE_NULL_LITERAL);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    break;
  case TOK_LPAREN:
    tok_poll_token(&tok);
    res = parse_expr();
    tok_expect_token(TOK_RPAREN, "\')\'");
    break;
  case TOK_IDENT:
    res = parse_array_elem_or_ident(TOK_IDENT);
    break;
  case TOK_EXCLAMATION_MARK:
  case TOK_LEN:
  case TOK_ORD:
  case TOK_CHR: {
    tok_poll_token(&tok);
    res = ast_alloc_node(AST_NODE_UNARY);
    res->token_id = tok.tok_kind;
    struct ast_node *child = parse_expr0();
    ast_set_tag(res, tok.tok_start,
                child->string_data + child->string_data_len - tok.tok_start);
    ast_add_first_child(res, child);
  } break;
  default:
    tok_report_unexpected(&tok, "primary expression");
  }

  return res;
}

#define PARSE_BINARY_FUNC(_name, _inner, ...)                                  \
  struct ast_node *_name() {                                                   \
    struct ast_node *lhs = _inner();                                           \
    while (true) {                                                             \
      struct tok tok;                                                          \
      if (!tok_peek_token(&tok)) {                                             \
        break;                                                                 \
      }                                                                        \
      if (__VA_ARGS__) {                                                       \
        tok_poll_token(&tok);                                                  \
        struct ast_node *rhs = _inner();                                       \
        struct ast_node *binop = ast_alloc_node(AST_NODE_BINARY);              \
        ast_set_tag(binop, tok.tok_start, tok.tok_size);                       \
        binop->token_id = tok.tok_kind;                                        \
        ast_add_first_child(binop, lhs);                                       \
        ast_add_next_child(lhs, rhs);                                          \
        lhs = binop;                                                           \
        continue;                                                              \
      }                                                                        \
      break;                                                                   \
    }                                                                          \
    return lhs;                                                                \
  }

PARSE_BINARY_FUNC(parse_expr1, parse_expr0,
                  tok.tok_kind == TOK_ASTERIX || tok.tok_kind == TOK_SLASH ||
                      tok.tok_kind == TOK_PERCENT_SIGN)

PARSE_BINARY_FUNC(parse_expr2, parse_expr1,
                  tok.tok_kind == TOK_PLUS_SIGN || tok.tok_kind == TOK_DASH)

PARSE_BINARY_FUNC(parse_expr3, parse_expr2,
                  tok.tok_kind == TOK_GT_SIGN || tok.tok_kind == TOK_LT_SIGN ||
                      tok.tok_kind == TOK_GE_SIGN ||
                      tok.tok_kind == TOK_LE_SIGN)

PARSE_BINARY_FUNC(parse_expr4, parse_expr3,
                  tok.tok_kind == TOK_EQ_SIGN || tok.tok_kind == TOK_NE_SIGN)

PARSE_BINARY_FUNC(parse_expr5, parse_expr4, tok.tok_kind == TOK_AND)

PARSE_BINARY_FUNC(parse_expr, parse_expr5, tok.tok_kind == TOK_OR)

struct ast_node *parse_array_literal() {
  struct ast_node *res = ast_alloc_node(AST_NODE_ARRAY_LITERAL);

  struct ast_node *last_child = NULL;
  struct tok tok;
  tok_extract_of_type(&tok, TOK_LBRACKET, "\'[\'");
  const char *start = tok.tok_start;

  tok_peek_token_no_eof(&tok, "expression or \']\'");
  if (tok.tok_kind == TOK_RBRACKET) {
    tok_poll_token(&tok);
    ast_set_tag(res, start, tok.tok_start + tok.tok_size - start);
    return res;
  }

  while (true) {
    ast_add_child(res, parse_expr(), &last_child);

    tok_peek_token_no_eof(&tok, "\',\' or \']\'");
    if (tok.tok_kind == TOK_RBRACKET) {
      tok_poll_token(&tok);
      ast_set_tag(res, start, tok.tok_start + tok.tok_size - start);
      return res;
    }
    tok_expect_token(TOK_COMMA, "\',\' or \']\'");
  }

  return res;
}

struct ast_node *parse_newpair() {
  struct tok tok;
  struct ast_node *res = ast_alloc_node(AST_NODE_RT_NEWPAIR);
  tok_extract_of_type(&tok, TOK_NEWPAIR, "newpair");
  const char *start = tok.tok_start;

  tok_expect_token(TOK_LPAREN, "\'(\'");
  struct ast_node *left = parse_expr();
  tok_expect_token(TOK_COMMA, "\',\'");
  struct ast_node *right = parse_expr();
  tok_extract_of_type(&tok, TOK_RPAREN, "\')\'");
  ast_set_tag(res, start, tok.tok_start + tok.tok_size - start);

  ast_add_first_child(res, left);
  ast_add_next_child(left, right);
  return res;
}

struct ast_node *parse_pair_elem() {
  struct tok tok;
  tok_poll_token_no_eof(&tok, "fst or snd");
  if (tok.tok_kind != TOK_FST && tok.tok_kind != TOK_SND) {
    tok_report_unexpected(&tok, "fst or snd");
  }
  struct ast_node *node = ast_alloc_node(AST_NODE_PAIR_ELEM);
  ast_set_tag(node, tok.tok_start, tok.tok_size);
  ast_add_first_child(node, parse_expr());
  node->token_id = tok.tok_kind;
  return node;
}

struct ast_node *parse_call() {
  struct tok tok;
  tok_expect_token(TOK_CALL, "call");
  tok_extract_of_type(&tok, TOK_IDENT, "identifier");
  tok_expect_token(TOK_LPAREN, "\'(\'");

  struct ast_node *node = ast_alloc_node(AST_NODE_CALL);
  struct ast_node *last_child = NULL;
  ast_set_tag(node, tok.tok_start, tok.tok_size);

  tok_peek_token_no_eof(&tok, "\')\' or expression");
  if (tok.tok_kind == TOK_RPAREN) {
    tok_poll_token(&tok);
    return node;
  }

  while (true) {
    struct ast_node *param = parse_expr();
    ast_add_child(node, param, &last_child);
    tok_poll_token_no_eof(&tok, "\',\' or \')\'");
    if (tok.tok_kind == TOK_RPAREN) {
      return node;
    } else if (tok.tok_kind == TOK_COMMA) {
      continue;
    }
    tok_report_unexpected(&tok, "\',\' or \')\'");
  }
}

struct ast_node *parse_assign_rhs() {
  struct ast_node *res;
  struct tok tok;
  tok_peek_token_no_eof(&tok, "rhs of assignment");

  switch (tok.tok_kind) {
  case TOK_LBRACKET:
    res = parse_array_literal();
    break;
  case TOK_NEWPAIR:
    res = parse_newpair();
    break;
  case TOK_FST:
  case TOK_SND:
    res = parse_pair_elem();
    break;
  case TOK_CALL:
    res = parse_call();
    break;
  default:
    res = parse_expr();
  }

  return res;
}

struct ast_node *parse_declaration_tail(struct ast_node *type,
                                        struct ast_node *ident) {
  tok_expect_token(TOK_ASSIGN, "\'=\'");
  struct ast_node *res = ast_alloc_node(AST_NODE_DECL);
  ast_set_tag(res, type->string_data, type->string_data_len);
  ast_add_first_child(res, type);
  ast_add_next_child(type, ident);
  ast_add_next_child(ident, parse_assign_rhs());
  return res;
}

struct ast_node *parse_declaration() {
  struct ast_node *type = parse_type();
  struct ast_node *ident = parse_ident();
  return parse_declaration_tail(type, ident);
}

struct ast_node *parse_assign_lhs() {
  struct tok tok;
  tok_peek_token_no_eof(&tok, "lhs of assignment");
  if (tok.tok_kind == TOK_FST || tok.tok_kind == TOK_SND) {
    return parse_pair_elem();
  }
  return parse_array_elem_or_ident();
}

struct ast_node *parse_assignment() {
  struct ast_node *result = ast_alloc_node(AST_NODE_ASSIGNMENT);

  struct ast_node *lhs = parse_assign_lhs();
  ast_set_tag(result, lhs->string_data, lhs->string_data_len);
  tok_expect_token(TOK_ASSIGN, "\'=\'");
  struct ast_node *rhs = parse_assign_rhs();
  ast_add_first_child(result, lhs);
  ast_add_next_child(lhs, rhs);
  return result;
}

struct ast_node *parse_scope();

struct ast_node *parse_explicit_scope() {
  struct tok tok;
  tok_extract_of_type(&tok, TOK_BEGIN, "begin");
  struct ast_node *res = parse_scope(TOK_END, "\';\' or end");
  ast_set_tag(res, tok.tok_start, tok.tok_size);
  tok_expect_token(TOK_END, "end");
  return res;
}

struct ast_node *parse_if() {
  struct ast_node *res = ast_alloc_node(AST_NODE_IF);

  struct tok tok;
  tok_extract_of_type(&tok, TOK_IF, "if");
  ast_set_tag(res, tok.tok_start, tok.tok_size);

  struct ast_node *cond = parse_expr();
  tok_expect_token(TOK_THEN, "then");
  struct ast_node *theng = parse_scope(TOK_ELSE, "\';\' or else");
  tok_expect_token(TOK_ELSE, "else");
  struct ast_node *elseg = parse_scope(TOK_FI, "\';\' or fi");
  tok_expect_token(TOK_FI, "fi");

  ast_add_first_child(res, cond);
  ast_add_next_child(cond, theng);
  ast_add_next_child(theng, elseg);

  return res;
}

struct ast_node *parse_while() {
  struct ast_node *res = ast_alloc_node(AST_NODE_WHILE);

  struct tok tok;
  tok_extract_of_type(&tok, TOK_WHILE, "while");
  ast_set_tag(res, tok.tok_start, tok.tok_size);

  struct ast_node *cond = parse_expr();
  tok_expect_token(TOK_DO, "do");
  struct ast_node *stmt = parse_scope(TOK_DONE, "\';\' or done");
  tok_expect_token(TOK_DONE, "done");

  ast_add_first_child(res, cond);
  ast_add_next_child(cond, stmt);

  return res;
}

struct ast_node *parse_statement_atom() {
  struct ast_node *res;
  struct tok tok;
  tok_peek_token_no_eof(&tok, "statement");
  switch (tok.tok_kind) {
  case TOK_SKIP:
    tok_poll_token(&tok);
    res = ast_alloc_node(AST_NODE_SKIP);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    break;
  case TOK_FREE:
  case TOK_EXIT:
  case TOK_PRINTLN:
  case TOK_PRINT:
  case TOK_RETURN:
    tok_poll_token(&tok);
    res = ast_alloc_node(tok.tok_kind == TOK_RETURN ? AST_NODE_RETURN
                                                    : AST_NODE_RT_CALL);
    res->token_id = tok.tok_kind;
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    ast_add_first_child(res, parse_expr());
    break;
  case TOK_READ:
    tok_poll_token(&tok);
    res = ast_alloc_node(AST_NODE_RT_READ);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    ast_add_first_child(res, parse_assign_lhs());
    break;
  case TOK_IDENT:
  case TOK_FST:
  case TOK_SND:
    res = parse_assignment();
    break;
  case TOK_IF:
    res = parse_if();
    break;
  case TOK_WHILE:
    res = parse_while();
    break;
  case TOK_BEGIN:
    res = parse_explicit_scope();
    break;
  default:
    res = parse_declaration();
    break;
  }
  return res;
}

// Do not forget to prepend "\';\'" to the term_expected_string, otherwise
// user will be confused
void parse_scope_in(struct ast_node *node, struct ast_node **last_child,
                    int term, const char *term_expected_string) {
  ast_add_child(node, parse_statement_atom(), last_child);
  ast_set_tag(node, (*last_child)->string_data, (*last_child)->string_data_len);
  while (true) {
    struct tok tok;
    if (!tok_peek_token(&tok) || (int)tok.tok_kind == term) {
      return;
    }
    tok_expect_token(TOK_SEMICOLON, term_expected_string);
    ast_add_child(node, parse_statement_atom(), last_child);
  }
}

struct ast_node *parse_scope(int term, const char *term_expected_string) {
  struct ast_node *res = ast_alloc_node(AST_NODE_SCOPE);
  struct ast_node *last_child = NULL;
  parse_scope_in(res, &last_child, term, term_expected_string);
  return res;
}

struct ast_node *parse_scope_tailing_decl(struct ast_node *type,
                                          struct ast_node *ident) {
  struct ast_node *res = ast_alloc_node(AST_NODE_SCOPE);
  struct ast_node *last_child = NULL;

  ast_add_child(res, parse_declaration_tail(type, ident), &last_child);

  struct tok tok;
  if (!tok_peek_token(&tok) || tok.tok_kind == TOK_END) {
    return res;
  }
  tok_expect_token(TOK_SEMICOLON, "\';\' or end");

  parse_scope_in(res, &last_child, TOK_END, "\';\' or end");
  return res;
}

struct ast_node *parse_parameter_list() {
  struct ast_node *result = ast_alloc_node(AST_NODE_PARAM_LIST);
  struct ast_node *last_child = NULL;
  struct tok tok;
  tok_extract_of_type(&tok, TOK_LPAREN, "\'(\'");
  ast_set_tag(result, tok.tok_start, tok.tok_size);

  tok_peek_token_no_eof(&tok, "\')\' or parameter definition");
  if (tok.tok_kind == TOK_RPAREN) {
    tok_poll_token(&tok);
    return result;
  }

  while (true) {
    struct ast_node *type = parse_type();
    struct ast_node *name = parse_ident();
    struct ast_node *param = ast_alloc_node(AST_NODE_PARAM);
    ast_set_tag(param, type->string_data,
                name->string_data + name->string_data_len - name->string_data);
    ast_add_first_child(param, type);
    ast_add_next_child(type, name);
    ast_add_child(result, param, &last_child);

    tok_peek_token_no_eof(&tok, "\',\' or \')\'");
    if (tok.tok_kind == TOK_RPAREN) {
      tok_poll_token(&tok);
      return result;
    }
    tok_expect_token(TOK_COMMA, "\',\' or \')\'");
  }

  return result;
}

struct ast_node *parse_extern() {
  struct ast_node *result = ast_alloc_node(AST_NODE_EXTERN);

  struct tok tok;
  tok_extract_of_type(&tok, TOK_EXTERN, "extern");

  struct ast_node *return_type = parse_type();
  struct ast_node *ident = parse_ident();
  struct ast_node *params = parse_parameter_list();

  ast_set_tag(result, tok.tok_start,
              params->string_data + params->string_data_len - tok.tok_start);
  ast_add_first_child(result, return_type);
  ast_add_next_child(return_type, ident);
  ast_add_next_child(ident, params);

  return result;
}

struct ast_node *parse_function_tail(struct ast_node *type,
                                     struct ast_node *ident) {
  struct ast_node *function = ast_alloc_node(AST_NODE_FUNC);
  ast_set_tag(function, type->string_data, type->string_data_len);
  struct ast_node *params = parse_parameter_list();
  tok_expect_token(TOK_IS, "is");
  struct ast_node *stmt = parse_scope(TOK_END, "\';\' or end");
  tok_expect_token(TOK_END, "end");

  ast_add_first_child(function, type);
  ast_add_next_child(type, ident);
  ast_add_next_child(ident, params);
  ast_add_next_child(params, stmt);
  return function;
}

struct ast_node *parse_program() {
  struct tok tok;
  tok_extract_of_type(&tok, TOK_BEGIN, "begin");
  const char *start = tok.tok_start;
  struct ast_node *res = ast_alloc_node(AST_NODE_PROGRAM);
  struct ast_node *cur_child = NULL;

  while (parse_on_type() || parse_on_extern()) {
    if (parse_on_extern()) {
      ast_add_child(res, parse_extern(), &cur_child);
      continue;
    }
    struct ast_node *type = parse_type();
    struct ast_node *ident = parse_ident();

    tok_peek_token_no_eof(&tok, "\'=\' or \'(\'");
    if (tok.tok_kind == TOK_ASSIGN) {
      ast_add_child(res, parse_scope_tailing_decl(type, ident), &cur_child);
      tok_expect_token(TOK_END, "end");
      return res;
    }
    ast_add_child(res, parse_function_tail(type, ident), &cur_child);
  }

  struct ast_node *statement = parse_scope(TOK_END, "\';\' or end");
  ast_add_child(res, statement, &cur_child);
  tok_extract_of_type(&tok, TOK_END, "end");
  ast_set_tag(res, start, tok.tok_start + tok.tok_size - start);

  size_t end_pos = source_pos;
  tok_skip_to_non_whitespace();
  if (source_pos != source_size) {
    struct pos pos;
    to_pos(end_pos, &pos);
    fprintf(stderr,
            "error at %s:%zu:%zu: junk past the end of the main program\n",
            source_path, pos.line, pos.column);
    exit(EXIT_SYNTAX_ERROR);
  }

  return res;
}

void mmap_ast_nodes() {
  ast_nodes = mmap(NULL, sizeof(struct ast_node) * AST_NODES_MAX,
                   PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (ast_nodes == MAP_FAILED) {
    perror("internal error: failed to map ast nodes pool");
    exit(EXIT_MISC_ERROR);
  }
}

void mmap_source() {
  int fd = open(source_path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "error: failed to open the source file \'%s\': %s",
            source_path, strerror(errno));
    exit(EXIT_MISC_ERROR);
  }

  struct stat source_stat;
  if (fstat(fd, &source_stat) != 0) {
    perror("internal error: failed to get source file size");
    exit(EXIT_MISC_ERROR);
  }
  source_size = source_stat.st_size;

  source =
      mmap(NULL, source_size, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
  if (source == MAP_FAILED) {
    perror("internal error: failed to map the source file");
    exit(EXIT_MISC_ERROR);
  }
}

void report_at_ast_node(struct ast_node *node, const char *severity,
                        const char *fmt, va_list args) {
  struct pos pos;
  to_pos(node->string_data - source, &pos);

  char buf[4096];
  vsnprintf(buf, 4096, fmt, args);

  fprintf(stderr, "%s at %s:%zu:%zu: %s\n", severity, source_path, pos.line,
          pos.column, buf);
}

void report_syntax_error_at_ast_node(struct ast_node *node, const char *fmt,
                                     ...) {
  va_list args;
  va_start(args, fmt);
  report_at_ast_node(node, "error", fmt, args);
  va_end(args);
  exit(EXIT_SYNTAX_ERROR);
}

static bool sema_checks_passed = true;

void sema_report_error_at(struct ast_node *node, const char *fmt, ...) {
  va_list args;
  sema_checks_passed = false;
  va_start(args, fmt);
  report_at_ast_node(node, "error", fmt, args);
  va_end(args);
}

void sema_show_note_at(struct ast_node *node, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  report_at_ast_node(node, "note", fmt, args);
  va_end(args);
}

void sema_assert_passed_checks() {
  if (!sema_checks_passed) {
    exit(EXIT_SEMANTIC_ERROR);
  }
}

void check_scope_returns(struct ast_node *scope) {
  struct ast_node *last = ast_last_child(scope);
  switch (last->kind) {
  case AST_NODE_RETURN:
    return;
  case AST_NODE_RT_CALL:
    if (last->token_id != TOK_EXIT) {
      report_syntax_error_at_ast_node(last,
                                      "return expected after this statement");
    }
    break;
  case AST_NODE_IF: {
    struct ast_node *theng = ast_nth_child(last, 1);
    struct ast_node *elseg = ast_nth_child(last, 2);
    check_scope_returns(theng);
    check_scope_returns(elseg);
  } break;
  case AST_NODE_SCOPE: {
    check_scope_returns(ast_first_child(last));
  } break;
  default:
    report_syntax_error_at_ast_node(last,
                                    "return expected after this statement");
  }
}

void check_returns_pass(struct ast_node *program) {
  struct ast_node *child = ast_first_child(program);
  while (child->kind == AST_NODE_FUNC || child->kind == AST_NODE_EXTERN) {
    if (child->kind == AST_NODE_EXTERN) {
      child = ast_next_child(child);
      continue;
    }
    struct ast_node *scope = ast_nth_child(child, 3);
    check_scope_returns(scope);
    child = ast_next_child(child);
  }
}

typedef size_t tkey_t;

struct type {
  tkey_t key;
  const char *name;
  enum {
    TYPE_UNINIT,
    TYPE_ARRAY,
    TYPE_PAIR,
  } kind;
  tindex_t args[2];
  const char *c_name;
  const char *c_free_name;
  const char *c_alloc_name;
};

#define TYPES_MAX 16777216

#define TYPE_STRIDE (tkey_t)2
#define TYPE_ARRAY_BASE (tkey_t)5
#define TYPE_PAIR_BASE (tkey_t)6

#define TINDEX_INT 0
#define TINDEX_BOOL 1
#define TINDEX_CHAR 2
#define TINDEX_STRING 3
#define TINDEX_PAIRPTR 4
#define TINDEX_CONSTRUCTOR_BASE 5

tkey_t type_array_compute_id(tindex_t elem_id) {
  return TYPE_ARRAY_BASE + TYPE_STRIDE * (tkey_t)elem_id;
}

tkey_t type_pair_compute_id(tindex_t left, tindex_t right) {
  return TYPE_PAIR_BASE +
         TYPE_STRIDE * ((tkey_t)left * TYPES_MAX + (tkey_t)right);
}

struct type *types;
void *types_tree = NULL;
tindex_t type_last_allocated_idx = 0;

void mmap_types() {
  types = mmap(NULL, sizeof(struct type) * TYPES_MAX, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (types == MAP_FAILED) {
    perror("internal error: failed to map type nodes pool");
    exit(EXIT_MISC_ERROR);
  }
}

int types_compare_keys(const void *left, const void *right) {
  tkey_t lkey = *(const tkey_t *)left;
  tkey_t rkey = *(const tkey_t *)right;
  if (lkey < rkey) {
    return -1;
  } else if (lkey == rkey) {
    return 0;
  }
  return 1;
}

struct type *type_find_key(tkey_t key) {
  struct type *res = tfind(&key, &types_tree, types_compare_keys);
  if (res != NULL) {
    return *(struct type **)res;
  }
  tindex_t idx = type_last_allocated_idx++;
  if (idx >= TYPES_MAX) {
    fprintf(stderr, "internal error: failed to allocate type node\n");
    exit(EXIT_MISC_ERROR);
  }
  struct type *node = types + idx;
  node->key = key;
  node->name = NULL;
  node->name = TYPE_UNINIT;
  if (tsearch(node, &types_tree, types_compare_keys) == NULL) {
    fprintf(stderr, "internal error: failed to construct type\n");
    exit(EXIT_MISC_ERROR);
  }
  return node;
}

const char *type_get_name(tindex_t index);

const char *dynamic_sprintf(const char *fmt, ...) {
  va_list args;
  va_list copy;
  va_start(args, fmt);
  va_copy(copy, args);

  size_t size = vsnprintf(NULL, 0, fmt, args) + 1;
  char *buf = alloc_eternal(size, 1);
  vsnprintf(buf, size, fmt, copy);

  va_end(args);
  va_end(copy);

  return buf;
}

const char *type_gen_name(struct type *type) {
  if (type->name != NULL) {
    return type->name;
  }
  switch (type->kind) {
  case TYPE_ARRAY:
    type->name = dynamic_sprintf("%s[]", type_get_name(type->args[0]));
    return type->name;
  case TYPE_PAIR:
    type->name = dynamic_sprintf("pair(%s, %s)", type_get_name(type->args[0]),
                                 type_get_name(type->args[1]));
    return type->name;
  default:
    __builtin_unreachable();
  }
}

const char *type_get_name(tindex_t index) {
  switch (index) {
  case TINDEX_INT:
    return "int";
  case TINDEX_BOOL:
    return "bool";
  case TINDEX_CHAR:
    return "char";
  case TINDEX_STRING:
    return "string";
  case TINDEX_PAIRPTR:
    return "pair";
  case TINDEX_INVALID:
    return "#invalid#";
  default: {
    struct type *type = types + index - TINDEX_CONSTRUCTOR_BASE;
    return type_gen_name(type);
  }
  }
}

tindex_t type_make_array(tindex_t inp) {
  tkey_t key = type_array_compute_id(inp);
  struct type *type = type_find_key(key);
  if (type->kind == TYPE_UNINIT) {
    type->kind = TYPE_ARRAY;
    type->args[0] = inp;
  }
  return type - types + TINDEX_CONSTRUCTOR_BASE;
}

tindex_t type_make_pair(tindex_t left, tindex_t right) {
  tkey_t key = type_pair_compute_id(left, right);
  struct type *type = type_find_key(key);
  if (type->kind == TYPE_UNINIT) {
    type->kind = TYPE_PAIR;
    type->args[0] = left;
    type->args[1] = right;
  }
  return type - types + TINDEX_CONSTRUCTOR_BASE;
}

tindex_t type_of_array_elem(tindex_t index) {
  if (index < TINDEX_CONSTRUCTOR_BASE) {
    return TINDEX_INVALID;
  }
  struct type *type = types + index - TINDEX_CONSTRUCTOR_BASE;
  if (type->kind != TYPE_ARRAY) {
    return TINDEX_INVALID;
  }
  return type->args[0];
}

tindex_t type_of_pair_elem(tindex_t index, int second) {
  if (index < TINDEX_CONSTRUCTOR_BASE) {
    return TINDEX_INVALID;
  }
  struct type *type = types + index - TINDEX_CONSTRUCTOR_BASE;
  if (type->kind != TYPE_PAIR) {
    return TINDEX_INVALID;
  }
  return type->args[second];
}

bool type_is_array(tindex_t index) {
  return type_of_array_elem(index) != TINDEX_INVALID;
}

bool type_is_pair(tindex_t index) {
  return type_of_pair_elem(index, 0) != TINDEX_INVALID;
}

bool type_pair_strict_subtype_of(tindex_t lhs, tindex_t rhs) {
  return (lhs == TINDEX_PAIRPTR && type_is_pair(rhs)) ||
         (type_is_pair(lhs) && rhs == TINDEX_PAIRPTR);
}

bool type_substitutable_for(tindex_t lhs, tindex_t rhs) {
  return lhs == rhs || lhs == TINDEX_INVALID || rhs == TINDEX_INVALID ||
         type_pair_strict_subtype_of(lhs, rhs);
}

bool types_eq_valid(tindex_t lhs, tindex_t rhs) {
  return type_substitutable_for(lhs, rhs);
}

tindex_t type_from_ast(struct ast_node *node) {
  switch (node->kind) {
  case AST_NODE_PRIMITIVE_TYPE:
    switch (node->token_id) {
    case TOK_INT:
      return TINDEX_INT;
    case TOK_BOOL:
      return TINDEX_BOOL;
    case TOK_CHAR:
      return TINDEX_CHAR;
    case TOK_STRING:
      return TINDEX_STRING;
    case TOK_PAIR:
      return TINDEX_PAIRPTR;
    default:
      __builtin_unreachable();
    }
  case AST_NODE_ARRAY:
    return type_make_array(type_from_ast(ast_first_child(node)));
  case AST_NODE_PAIR:
    return type_make_pair(type_from_ast(ast_first_child(node)),
                          type_from_ast(ast_nth_child(node, 1)));
  default:
    __builtin_unreachable();
  }
}

// https://stackoverflow.com/questions/7666509/hash-function-for-string
inline static uint64_t MurmurOAAT64(const char *key, size_t len) {
  uint64_t h = 525201411107845655ull;
  for (size_t i = 0; i < len; ++i) {
    h ^= *key;
    h *= 0x5bd1e9955bd1e995;
    h ^= h >> 47;
  }
  return h;
}

struct symbol {
  struct symbol *prev;
  uint64_t hash;
  const char *str;
  size_t len;
  struct ast_node *ident;
  int scope_id;
  tindex_t tindex;
  bool writable;
};

struct symbol *symbol_find(struct symbol *table, const char *str, size_t len,
                           int scope_id) {
  uint64_t hash = MurmurOAAT64(str, len);
  while (table != NULL) {
    if (scope_id != -1 && table->scope_id != scope_id) {
      return NULL;
    }
    if (table->hash == hash && table->len == len &&
        memcmp(table->str, str, len) == 0) {
      return table;
    }
    table = table->prev;
  }
  return NULL;
}

void symbol_init(struct symbol *symbol, struct symbol *table,
                 struct ast_node *ident, int scope_id, tindex_t index,
                 bool writable) {
  symbol->str = ident->string_data;
  symbol->len = ident->string_data_len;
  symbol->prev = table;
  symbol->hash = MurmurOAAT64(symbol->str, symbol->len);
  symbol->ident = ident;
  symbol->scope_id = scope_id;
  symbol->tindex = index;
  symbol->writable = writable;

  struct symbol *prev = symbol_find(table, symbol->str, symbol->len, scope_id);
  if (prev != NULL) {
    sema_report_error_at(ident, "redefinition of \'%.*s\'", symbol->len,
                         symbol->str);
    sema_show_note_at(prev->ident, "previous definition of \'%.*s\' is here",
                      symbol->len, symbol->str);
  }
}

#define symbol_push(_prev, _decl, _scope_id, _tindex, _writable)               \
  ({                                                                           \
    struct symbol *_ptr = alloca(sizeof(struct symbol));                       \
    symbol_init(_ptr, _prev, _decl, _scope_id, _tindex, _writable);            \
    _ptr;                                                                      \
  })

struct function_name {
  const char *name;
  size_t len;
  uint64_t hash;
};

struct function {
  struct function_name name;
  tindex_t *argument_types;
  uint32_t arguments_count;
  tindex_t return_type;
  struct ast_node *node;
};

#define FUNCTIONS_MAX 16777216

struct function *functions;
size_t functions_count = 0;
void *functions_tree;

int function_names_compare(const void *lhs, const void *rhs) {
  const struct function_name *lfunc = lhs;
  const struct function_name *rfunc = rhs;
  if (lfunc->hash < rfunc->hash) {
    return -1;
  } else if (lfunc->hash > rfunc->hash) {
    return 1;
  }
  return strncmp(lfunc->name, rfunc->name, lfunc->len);
}

void mmap_functions() {
  functions = mmap(NULL, FUNCTIONS_MAX * sizeof(struct function),
                   PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (functions == MAP_FAILED) {
    perror("internal error: failed to map functions pool");
    exit(EXIT_MISC_ERROR);
  }
}

struct function *function_alloc() {
  if (functions_count >= FUNCTIONS_MAX) {
    fprintf(stderr,
            "internal error: failed to allocate space for a new function");
    exit(EXIT_MISC_ERROR);
  }
  return functions + functions_count++;
}

struct function *function_lookup(const char *name, size_t len) {
  struct function_name name_struct;
  name_struct.name = name;
  name_struct.len = len;
  name_struct.hash = MurmurOAAT64(name, len);
  void **resptr = tfind(&name_struct, &functions_tree, function_names_compare);
  if (resptr == NULL) {
    return NULL;
  }
  return *resptr;
}

void function_from_ast_node(struct ast_node *node) {
  struct ast_node *return_type_node = ast_first_child(node);
  struct ast_node *name_node = ast_next_child(return_type_node);
  struct ast_node *param_list = ast_next_child(name_node);

  struct function *func =
      function_lookup(name_node->string_data, name_node->string_data_len);
  if (func != NULL) {
    sema_report_error_at(node, "redeclaration of function \"%.*s\"",
                         name_node->string_data_len, name_node->string_data);
    sema_show_note_at(func->node, "previously declared here");
    return;
  }

  func = function_alloc();
  func->return_type = type_from_ast(return_type_node);
  func->name.name = name_node->string_data;
  func->name.len = name_node->string_data_len;
  func->name.hash = MurmurOAAT64(func->name.name, func->name.len);
  func->arguments_count = ast_count_children(param_list);
  func->node = node;

  func->argument_types =
      alloc_eternal(sizeof(tindex_t) * func->arguments_count, 4);
  struct ast_node *param = ast_first_child(param_list);
  uint32_t current_index = 0;
  while (param != NULL) {
    func->argument_types[current_index++] =
        type_from_ast(ast_first_child(param));
    param = ast_next_child(param);
  }

  if (tsearch(func, &functions_tree, function_names_compare) == NULL) {
    fprintf(stderr, "internal error: failed to add a new function to the "
                    "lookup tree\n");
    exit(EXIT_MISC_ERROR);
  }
}

void functions_pass(struct ast_node *program) {
  struct ast_node *function = ast_first_child(program);
  while (function->kind == AST_NODE_FUNC || function->kind == AST_NODE_EXTERN) {
    function_from_ast_node(function);
    function = ast_next_child(function);
  }
}

void sema_visit_ident(struct symbol *table, struct ast_node *ident) {
  struct symbol *sym =
      symbol_find(table, ident->string_data, ident->string_data_len, -1);
  if (sym == NULL) {
    sema_report_error_at(ident, "\'%.*s\' undeclared", ident->string_data_len,
                         ident->string_data);
    return;
  }
  ident->tindex = sym->tindex;
}

void sema_visit_expr(struct symbol *table, struct ast_node *rhs);

void sema_visit_pair_elem(struct symbol *table, struct ast_node *pair_elem) {
  bool index = pair_elem->token_id == TOK_SND;
  struct ast_node *pair = ast_first_child(pair_elem);
  sema_visit_expr(table, pair);
  if (pair->tindex == TINDEX_INVALID) {
    return;
  }
  tindex_t elem_type = type_of_pair_elem(pair->tindex, index);
  if (elem_type == TINDEX_INVALID) {
    sema_report_error_at(pair, "expression of type \'%s\' is not a pair",
                         type_get_name(pair->tindex));
  }
  pair_elem->tindex = elem_type;
}

void sema_visit_binary_operator(struct symbol *table, struct ast_node *node) {
  int operator_token = node->token_id;
  struct ast_node *lhs = ast_first_child(node);
  struct ast_node *rhs = ast_next_child(lhs);

  sema_visit_expr(table, lhs);
  sema_visit_expr(table, rhs);

  if (lhs->tindex == TINDEX_INVALID || rhs->tindex == TINDEX_INVALID) {
    return;
  }

  switch (operator_token) {
  case TOK_GT_SIGN:
  case TOK_GE_SIGN:
  case TOK_LT_SIGN:
  case TOK_LE_SIGN:
    if (lhs->tindex == TINDEX_CHAR || rhs->tindex == TINDEX_INT) {
      node->tindex = TINDEX_BOOL;
      return;
    }
    // fallthrough
  case TOK_ASTERIX:
  case TOK_SLASH:
  case TOK_PERCENT_SIGN:
  case TOK_PLUS_SIGN:
  case TOK_DASH:
    if (lhs->tindex == TINDEX_INT && rhs->tindex == TINDEX_INT) {
      node->tindex = TINDEX_INT;
      return;
    }
    break;
  case TOK_AND:
  case TOK_OR:
    if (lhs->tindex == TINDEX_BOOL && rhs->tindex == TINDEX_BOOL) {
      node->tindex = TINDEX_BOOL;
      return;
    }
    break;
  case TOK_EQ_SIGN:
  case TOK_NE_SIGN:
    if (types_eq_valid(lhs->tindex, rhs->tindex)) {
      node->tindex = TINDEX_BOOL;
      return;
    }
    return;
  }
  sema_report_error_at(node,
                       "invalid operands to binary '%.*s' (have '%s' and '%s')",
                       node->string_data_len, node->string_data,
                       type_get_name(lhs->tindex), type_get_name(rhs->tindex));
}

void sema_visit_unary_operator(struct symbol *table, struct ast_node *node) {
  int operator_token = node->token_id;
  struct ast_node *inp = ast_first_child(node);

  sema_visit_expr(table, inp);
  if (inp->tindex == TINDEX_INVALID) {
    return;
  }

  switch (operator_token) {
  case TOK_DASH:
    if (inp->tindex == TINDEX_INT) {
      node->tindex = TINDEX_INT;
      return;
    }
    break;
  case TOK_LEN:
    if (type_is_array(inp->tindex)) {
      node->tindex = TINDEX_INT;
      return;
    }
    break;
  case TOK_ORD:
    if (inp->tindex == TINDEX_CHAR) {
      node->tindex = TINDEX_INT;
      return;
    }
    break;
  case TOK_CHR:
    if (inp->tindex == TINDEX_INT) {
      node->tindex = TINDEX_CHAR;
      return;
    }
    break;
  case TOK_EXCLAMATION_MARK:
    if (inp->tindex == TINDEX_BOOL) {
      node->tindex = TINDEX_BOOL;
      return;
    }
    break;
  }

  sema_report_error_at(node, "wrong type argument to unary '%.*s'",
                       node->string_data_len, node->string_data,
                       type_get_name(inp->tindex));
}

void sema_visit_array_elem(struct symbol *table, struct ast_node *node) {
  struct ast_node *ident_node = ast_first_child(node);
  sema_visit_ident(table, ident_node);

  tindex_t result = ident_node->tindex;
  struct ast_node *subscript = ast_next_child(ident_node);
  while (subscript != NULL) {
    sema_visit_expr(table, subscript);
    if (subscript->tindex != TINDEX_INT &&
        subscript->tindex != TINDEX_INVALID) {
      sema_report_error_at(node, "array subscript is not an integer");
      return;
    }
    tindex_t next = type_of_array_elem(result);
    if (next == TINDEX_INVALID) {
      sema_report_error_at(
          node, "subscripted value is not an array or lacks dimensions");
      return;
    }
    result = next;
    subscript = ast_next_child(subscript);
  }

  node->tindex = result;
}

void sema_visit_call(struct symbol *table, struct ast_node *call) {
  (void)table;
  struct function *function =
      function_lookup(call->string_data, call->string_data_len);
  if (function == NULL) {
    sema_report_error_at(call, "use of undeclared function \"%.*s\"",
                         call->string_data_len, call->string_data);
    return;
  }
  uint32_t args_count = 0;
  struct ast_node *arg = ast_first_child(call);
  while (arg != NULL) {
    sema_visit_expr(table, arg);
    uint32_t arg_idx = args_count++;
    if (arg_idx < function->arguments_count) {
      tindex_t expected = function->argument_types[arg_idx];
      tindex_t got = arg->tindex;
      if (!type_substitutable_for(got, expected)) {
        sema_report_error_at(
            arg, "passing '%s' to parameter of incompatible type '%s'",
            type_get_name(got), type_get_name(expected));
      }
    }
    arg = ast_next_child(arg);
  }

  if (args_count < function->arguments_count) {
    sema_report_error_at(
        call, "too few arguments to function call (expected %u, got %u)",
        function->arguments_count, args_count);
  } else if (args_count > function->arguments_count) {
    sema_report_error_at(
        call, "too many arguments to function call (expected %u, got %u)",
        function->arguments_count, args_count);
  }
  call->tindex = function->return_type;
}

void sema_check_init_with(struct ast_node *node, tindex_t expected) {
  if (!type_substitutable_for(node->tindex, expected)) {
    sema_report_error_at(node,
                         "initializing '%s' with an expression of type '%s'",
                         type_get_name(expected), type_get_name(node->tindex));
  }
}

void sema_visit_array_literal(struct symbol *table, struct ast_node *literal,
                              tindex_t array_type) {
  literal->tindex = array_type;
  tindex_t elem_type = array_type == TINDEX_INVALID
                           ? TINDEX_INVALID
                           : type_of_array_elem(array_type);
  if (elem_type == TINDEX_INVALID && array_type != TINDEX_INVALID) {
    sema_report_error_at(literal, "array literal not expected here");
    return;
  }
  struct ast_node *elem = ast_first_child(literal);
  if (elem == NULL) {
    return;
  }
  while (elem != NULL) {
    sema_visit_expr(table, elem);
    sema_check_init_with(elem, elem_type);
    elem = ast_next_child(elem);
  }
}

void sema_visit_newpair(struct symbol *table, struct ast_node *newpair,
                        tindex_t pair_type) {
  newpair->tindex = pair_type;

  struct ast_node *left = ast_first_child(newpair);
  struct ast_node *right = ast_next_child(left);
  sema_visit_expr(table, left);
  sema_visit_expr(table, right);

  tindex_t left_elem = type_of_pair_elem(pair_type, 0);
  tindex_t right_elem = type_of_pair_elem(pair_type, 1);
  if (left_elem == TINDEX_INVALID) {
    sema_report_error_at(newpair, "newpair not expected here");
    return;
  }
  sema_check_init_with(left, left_elem);
  sema_check_init_with(right, right_elem);
}

void sema_visit_expr(struct symbol *table, struct ast_node *expr) {
  switch (expr->kind) {
  case AST_NODE_IDENT:
    sema_visit_ident(table, expr);
    break;
  case AST_NODE_ARRAY_ELEM:
    sema_visit_array_elem(table, expr);
    break;
  case AST_NODE_PAIR_ELEM:
    sema_visit_pair_elem(table, expr);
    break;
  case AST_NODE_CALL:
    sema_visit_call(table, expr);
    break;
  case AST_NODE_UNARY:
    sema_visit_unary_operator(table, expr);
    break;
  case AST_NODE_BINARY:
    sema_visit_binary_operator(table, expr);
    break;
  case AST_NODE_INT_LITERAL:
    expr->tindex = TINDEX_INT;
    break;
  case AST_NODE_BOOL_LITERAL:
    expr->tindex = TINDEX_BOOL;
    break;
  case AST_NODE_CHAR_LITERAL:
    expr->tindex = TINDEX_CHAR;
    break;
  case AST_NODE_STRING_LITERAL:
    expr->tindex = TINDEX_STRING;
    break;
  case AST_NODE_NULL_LITERAL:
    expr->tindex = TINDEX_PAIRPTR;
    break;
  default:
    __builtin_unreachable();
  }
}

void sema_visit_assign_lhs(struct symbol *table, struct ast_node *lhs) {
  switch (lhs->kind) {
  case AST_NODE_IDENT:
    sema_visit_ident(table, lhs);
    break;
  case AST_NODE_ARRAY_ELEM:
    sema_visit_array_elem(table, lhs);
    break;
  case AST_NODE_PAIR_ELEM:
    sema_visit_pair_elem(table, lhs);
    break;
  default:
    __builtin_unreachable();
  }
}

void sema_visit_return(struct symbol *table, struct ast_node *node,
                       tindex_t return_type) {
  if (return_type == TINDEX_INVALID) {
    sema_report_error_at(node, "attempt to return from the main program");
    return;
  }
  struct ast_node *expr = ast_first_child(node);
  sema_visit_expr(table, expr);
  if (!type_substitutable_for(expr->tindex, return_type)) {
    sema_report_error_at(
        node,
        "incompatible types when returning type '%s' but '%s' was expected",
        type_get_name(expr->tindex), type_get_name(return_type));
  }
}

void sema_visit_assign_rhs(struct symbol *table, struct ast_node *rhs,
                           tindex_t constraint) {
  switch (rhs->kind) {
  case AST_NODE_RT_NEWPAIR:
    sema_visit_newpair(table, rhs, constraint);
    break;
  case AST_NODE_ARRAY_LITERAL:
    sema_visit_array_literal(table, rhs, constraint);
    break;
  default:
    sema_visit_expr(table, rhs);
    sema_check_init_with(rhs, constraint);
  }
}

void sema_visit_decl(struct symbol *table, struct ast_node *decl) {
  struct ast_node *type = ast_first_child(decl);
  struct ast_node *expr = ast_nth_child(decl, 2);
  sema_visit_assign_rhs(table, expr, type_from_ast(type));
}

void sema_visit_assignment(struct symbol *table, struct ast_node *assignment) {
  struct ast_node *lhs = ast_first_child(assignment);
  struct ast_node *rhs = ast_next_child(lhs);
  sema_visit_assign_lhs(table, lhs);
  sema_visit_assign_rhs(table, rhs, lhs->tindex);
}

void sema_visit_rt_call(struct symbol *table, struct ast_node *rt_call) {
  struct ast_node *arg = ast_first_child(rt_call);
  sema_visit_expr(table, arg);
  switch (rt_call->token_id) {
  case TOK_FREE:
    if (arg->tindex < TINDEX_CONSTRUCTOR_BASE &&
        arg->tindex != TINDEX_PAIRPTR) {
      sema_report_error_at(arg,
                           "attempt to free value of primitive type \"%s\"",
                           type_get_name(rt_call->tindex));
    }
    break;
  case TOK_EXIT:
    if (!type_substitutable_for(TINDEX_INT, arg->tindex)) {
      sema_report_error_at(arg, "exit codes can only be integers");
    }
    break;
  default:
    break;
  }
}

void sema_visit_rt_read(struct symbol *table, struct ast_node *rt_call) {
  struct ast_node *arg = ast_first_child(rt_call);
  sema_visit_assign_lhs(table, arg);
  if (!type_substitutable_for(arg->tindex, TINDEX_INT) &&
      !type_substitutable_for(arg->tindex, TINDEX_CHAR)) {
    sema_report_error_at(
        arg, "attempt to read into location of unsupported type \'%s\'",
        type_get_name(arg->tindex));
  }
}

void sema_visit_scope(struct symbol *table, int scope_id,
                      struct ast_node *scope, tindex_t return_type);

void sema_visit_if(struct symbol *table, int scope_id, struct ast_node *ifstmt,
                   tindex_t return_type) {
  struct ast_node *cond = ast_first_child(ifstmt);
  struct ast_node *theng = ast_next_child(cond);
  struct ast_node *elseg = ast_next_child(theng);

  sema_visit_expr(table, cond);
  if (!type_substitutable_for(cond->tindex, TINDEX_BOOL)) {
    sema_report_error_at(cond,
                         "if statement condition has to be a boolean value "
                         "(got type \'%s\' instead)",
                         type_get_name(cond->tindex));
  }

  sema_visit_scope(table, scope_id + 1, theng, return_type);
  sema_visit_scope(table, scope_id + 1, elseg, return_type);
}

void sema_visit_while(struct symbol *table, int scope_id,
                      struct ast_node *whilestmt, tindex_t return_type) {
  struct ast_node *cond = ast_first_child(whilestmt);
  struct ast_node *body = ast_next_child(cond);

  sema_visit_expr(table, cond);
  if (!type_substitutable_for(cond->tindex, TINDEX_BOOL)) {
    sema_report_error_at(cond,
                         "while loop condition has to be a boolean value (got "
                         "type \'%s\' instead)",
                         type_get_name(cond->tindex));
  }

  sema_visit_scope(table, scope_id + 1, body, return_type);
}

void sema_visit_scope(struct symbol *table, int scope_id,
                      struct ast_node *scope, tindex_t return_type) {
  struct ast_node *stmt = ast_first_child(scope);
  while (stmt != NULL) {
    switch (stmt->kind) {
    case AST_NODE_DECL:
      table = symbol_push(table, ast_nth_child(stmt, 1), scope_id,
                          type_from_ast(ast_first_child(stmt)), true);
      sema_visit_decl(table, stmt);
      break;
    case AST_NODE_ASSIGNMENT:
      sema_visit_assignment(table, stmt);
      break;
    case AST_NODE_SKIP:
      break;
    case AST_NODE_RT_CALL:
      sema_visit_rt_call(table, stmt);
      break;
    case AST_NODE_RETURN:
      sema_visit_return(table, stmt, return_type);
      break;
    case AST_NODE_RT_READ:
      sema_visit_rt_read(table, stmt);
      break;
    case AST_NODE_IF:
      sema_visit_if(table, scope_id, stmt, return_type);
      break;
    case AST_NODE_WHILE:
      sema_visit_while(table, scope_id, stmt, return_type);
      break;
    case AST_NODE_SCOPE:
      sema_visit_scope(table, scope_id + 1, stmt, return_type);
      break;
    default:
      __builtin_unreachable();
    }
    stmt = ast_next_child(stmt);
  }
}

void sema_visit_function(struct ast_node *node) {
  tindex_t return_index = type_from_ast(ast_first_child(node));

  struct ast_node *param_list = ast_nth_child(node, 2);
  struct symbol *table = NULL;
  struct ast_node *param = ast_first_child(param_list);

  while (param != NULL) {
    struct ast_node *name = ast_nth_child(param, 1);
    table = symbol_push(table, name, 0, type_from_ast(ast_first_child(param)),
                        false);
    param = ast_next_child(param);
  }

  struct ast_node *scope = ast_nth_child(node, 3);
  sema_visit_scope(table, 0, scope, return_index);
}

void sema_main_pass(struct ast_node *program) {
  struct ast_node *child = ast_first_child(program);
  while (child->kind == AST_NODE_FUNC || child->kind == AST_NODE_EXTERN) {
    if (child->kind == AST_NODE_FUNC) {
      sema_visit_function(child);
    }
    child = ast_next_child(child);
  }
  sema_visit_scope(NULL, 0, child, TINDEX_INVALID);
}

bool verify_extension(const char *path) {
  size_t len = strlen(path);
  size_t extension_len = strlen(WACC_EXTENSION);
  return memcmp(path + len - extension_len, WACC_EXTENSION, extension_len) == 0;
}

FILE *output_file;

#define CGEN_IDENT_SEQ "\t"
#define CGEN_PRELUDE                                                           \
  "typedef int Int;\n"                                                         \
  "typedef char Char;\n"                                                       \
  "typedef _Bool Bool;\n"                                                      \
  "typedef const char *String;\n"                                              \
  "typedef void *PairPtr;\n"                                                   \
  "static const _Bool true = 1;\n"                                             \
  "static const _Bool false = 0;\n"                                            \
  "static void *const null = (void *)0;\n"                                     \
  "\n"                                                                         \
  "int $arrayLength(const void *s) { long unsigned int *ss = (long unsigned "  \
  "int *)s; return "                                                           \
  "(Int)*(ss "                                                                 \
  "- 1); }\n\n"                                                                \
  "Int printf(const char *restrict format, ...);\n"                            \
  "Int scanf(const char *restrict format, ...);\n"                             \
  "void *memcpy(void *restrict dest, const void *restrict src, long unsigned " \
  "int n);\n"                                                                  \
  "__attribute__((noreturn)) void exit(int status);\n"                         \
  "void *malloc(long unsigned int size);\n"                                    \
  "void free(void *ptr);\n"                                                    \
  "\n"                                                                         \
  "void $printCharArray(String arr, Bool newline) { int len = "                \
  "$arrayLength(arr); printf(newline ? \"%.*s\\n\" : \"%.*s\", len, arr); } "  \
  "\n"

void cgen_emit_sep() { fputc('\n', output_file); }

void cgen_emit_line(int ident_level, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
  vfprintf(output_file, fmt, args);
  cgen_emit_sep();

  va_end(args);
}

const char *cgen_get_type_name(tindex_t index) {
  switch (index) {
  case TINDEX_INT:
    return "Int";
  case TINDEX_BOOL:
    return "Bool";
  case TINDEX_CHAR:
    return "Char";
  case TINDEX_STRING:
    return "String";
  case TINDEX_PAIRPTR:
    return "PairPtr";
  default:
    return (types + index - TINDEX_CONSTRUCTOR_BASE)->c_name;
  }
}

void cgen_emit_typedef(struct type *type) {
  switch (type->kind) {
  case TYPE_ARRAY: {
    const char *elem_name = cgen_get_type_name(type->args[0]);
    const char *array_name = dynamic_sprintf("ArrayOf%s", elem_name);
    const char *alloc_name = dynamic_sprintf("$alloc%s", array_name);
    const char *free_name = dynamic_sprintf("$free%s", array_name);

    type->c_name = array_name;
    type->c_alloc_name = alloc_name;
    type->c_free_name = free_name;

    cgen_emit_line(0, "typedef %s* %s;", elem_name, array_name);
    cgen_emit_sep();

    cgen_emit_line(0, "%s %s(%s *elems, int count) {", array_name, alloc_name,
                   elem_name);
    cgen_emit_line(1,
                   "unsigned long int memory_needed = (unsigned long int)count "
                   "* sizeof(%s) + sizeof(unsigned long int);",
                   elem_name);
    cgen_emit_line(1, "unsigned long int *res = malloc(memory_needed);");
    cgen_emit_line(1, "if (res == null) return null;");
    cgen_emit_line(1, "*res = (unsigned long int)count;");
    cgen_emit_line(
        1, "memcpy(res + 1, elems, (unsigned long int)count * sizeof(%s));",
        elem_name);
    cgen_emit_line(1, "return (%s)(res + 1);", array_name);
    cgen_emit_line(0, "}");
    cgen_emit_sep();

    cgen_emit_line(0, "void %s(%s ptr) {", free_name, array_name);
    cgen_emit_line(1, "free((unsigned long int *)ptr - 1);");
    cgen_emit_line(0, "}");
  } break;
  case TYPE_PAIR: {
    const char *fst_name = cgen_get_type_name(type->args[0]);
    const char *snd_name = cgen_get_type_name(type->args[1]);
    const char *pair_name =
        dynamic_sprintf("PairOf%sAnd%s", fst_name, snd_name);
    const char *alloc_name = dynamic_sprintf("$alloc%s", pair_name);
    const char *free_name = "free";
    type->c_name = pair_name;
    type->c_alloc_name = alloc_name;
    type->c_free_name = free_name;

    cgen_emit_line(0, "typedef struct {");
    cgen_emit_line(1, "%s fst;", fst_name);
    cgen_emit_line(1, "%s snd;", snd_name);
    cgen_emit_line(0, "} *%s;", pair_name);
    cgen_emit_sep();

    cgen_emit_line(0, "%s %s(%s fst, %s snd) {", pair_name, alloc_name,
                   fst_name, snd_name);
    cgen_emit_line(1, "%s res = malloc(sizeof(*res));", pair_name);
    cgen_emit_line(1, "res->fst = fst;");
    cgen_emit_line(1, "res->snd = snd;");
    cgen_emit_line(1, "return res;");
    cgen_emit_line(0, "}");
  } break;
  default:
    __builtin_unreachable();
  }
}

void cgen_emit_func_decl_impl(struct function *function, bool mangle) {
  fprintf(output_file, mangle ? "%s $%.*s(" : "%s %.*s(",
          cgen_get_type_name(function->return_type), (int)function->name.len,
          function->name.name);
  if (function->arguments_count == 0) {
    fprintf(output_file, ")");
    return;
  }
  for (uint32_t i = 0; i < function->arguments_count - 1; ++i) {
    fprintf(output_file, "%s, ",
            cgen_get_type_name(function->argument_types[i]));
  }
  fprintf(output_file, "%s)",
          cgen_get_type_name(
              function->argument_types[function->arguments_count - 1]));
}

void cgen_emit_func_decl(struct function *function) {
  if (function->node->kind == AST_NODE_EXTERN) {
    cgen_emit_func_decl_impl(function, false);
    fprintf(output_file, ";\n");
    fprintf(output_file, "__auto_type $%.*s = %.*s;\n", (int)function->name.len,
            function->name.name, (int)function->name.len, function->name.name);
  } else {
    cgen_emit_func_decl_impl(function, true);
    fprintf(output_file, ";\n");
  }
}

void cgen_emit_func_decls() {
  for (size_t i = 0; i < functions_count; ++i) {
    cgen_emit_func_decl(functions + i);
  }
}

void cgen_emit_assign_rhs(struct ast_node *rhs);

void cgen_emit_array_literal(struct ast_node *rhs) {
  struct type *type = types + rhs->tindex - TINDEX_CONSTRUCTOR_BASE;
  const char *elem_type_name =
      cgen_get_type_name(type_of_array_elem(rhs->tindex));
  fprintf(output_file, "%s((%s[]){", type->c_alloc_name, elem_type_name);
  struct ast_node *elem = ast_first_child(rhs);
  int elems_count = 0;
  while (elem != NULL) {
    struct ast_node *next_elem = ast_next_child(elem);
    elems_count++;
    cgen_emit_assign_rhs(elem);
    if (next_elem != NULL) {
      fprintf(output_file, ", ");
    }
    elem = next_elem;
  }
  fprintf(output_file, "}, %d)", elems_count);
}

void cgen_emit_newpair(struct ast_node *rhs) {
  struct type *type = types + rhs->tindex - TINDEX_CONSTRUCTOR_BASE;
  fprintf(output_file, "%s(", type->c_alloc_name);
  cgen_emit_assign_rhs(ast_first_child(rhs));
  fprintf(output_file, ", ");
  cgen_emit_assign_rhs(ast_nth_child(rhs, 1));
  fprintf(output_file, ")");
}

void cgen_emit_call(struct ast_node *node) {
  struct function *function =
      function_lookup(node->string_data, node->string_data_len);
  bool external = function->node->kind == AST_NODE_EXTERN;
  fprintf(output_file, external ? "%.*s(" : "$%.*s(", node->string_data_len,
          node->string_data);
  struct ast_node *arg = ast_first_child(node);
  while (arg != NULL) {
    struct ast_node *next_arg = ast_next_child(arg);
    cgen_emit_assign_rhs(arg);
    if (next_arg != NULL) {
      fprintf(output_file, ", ");
    }
    arg = next_arg;
  };
  fprintf(output_file, ")");
}

void cgen_emit_array_elem(struct ast_node *node) {
  struct ast_node *ident = ast_first_child(node);
  cgen_emit_assign_rhs(ident);
  struct ast_node *elem = ast_next_child(ident);
  while (elem != NULL) {
    fprintf(output_file, "[");
    cgen_emit_assign_rhs(elem);
    fprintf(output_file, "]");
    elem = ast_next_child(elem);
  }
}

void cgen_emit_ident(struct ast_node *rhs) {
  const char *str = rhs->string_data;
  int len = rhs->string_data_len;
#define CGEN_HANDLE_C_KEYWORD(_k)                                              \
  if (len == strlen(_k) && memcmp(str, _k, len) == 0) {                        \
    str = "$"_k;                                                               \
    len = strlen(_k) + 1;                                                      \
    goto emit;                                                                 \
  }
  switch (str[0]) {
  case 'a':
    CGEN_HANDLE_C_KEYWORD("auto")
    break;
  case 'b':
    CGEN_HANDLE_C_KEYWORD("break")
    break;
  case 'c':
    CGEN_HANDLE_C_KEYWORD("case")
    CGEN_HANDLE_C_KEYWORD("const")
    CGEN_HANDLE_C_KEYWORD("continue")
    break;
  case 'd':
    CGEN_HANDLE_C_KEYWORD("default")
    CGEN_HANDLE_C_KEYWORD("double")
    break;
  case 'e':
    CGEN_HANDLE_C_KEYWORD("enum")
    CGEN_HANDLE_C_KEYWORD("exit")
    CGEN_HANDLE_C_KEYWORD("extern")
    break;
  case 'f':
    CGEN_HANDLE_C_KEYWORD("float")
    CGEN_HANDLE_C_KEYWORD("for")
    CGEN_HANDLE_C_KEYWORD("free")
    break;
  case 'g':
    CGEN_HANDLE_C_KEYWORD("goto")
    break;
  case 'i':
    CGEN_HANDLE_C_KEYWORD("inline")
    break;
  case 'l':
    CGEN_HANDLE_C_KEYWORD("long")
    break;
  case 'm':
    CGEN_HANDLE_C_KEYWORD("malloc")
    CGEN_HANDLE_C_KEYWORD("memcpy")
    break;
  case 'p':
    CGEN_HANDLE_C_KEYWORD("printf")
    break;
  case 'r':
    CGEN_HANDLE_C_KEYWORD("register")
    CGEN_HANDLE_C_KEYWORD("restrict")
    break;
  case 's':
    CGEN_HANDLE_C_KEYWORD("scanf")
    CGEN_HANDLE_C_KEYWORD("short")
    CGEN_HANDLE_C_KEYWORD("signed")
    CGEN_HANDLE_C_KEYWORD("sizeof")
    CGEN_HANDLE_C_KEYWORD("static")
    CGEN_HANDLE_C_KEYWORD("struct")
    CGEN_HANDLE_C_KEYWORD("switch")
    break;
  case 't':
    CGEN_HANDLE_C_KEYWORD("typedef")
    break;
  case 'u':
    CGEN_HANDLE_C_KEYWORD("union")
    CGEN_HANDLE_C_KEYWORD("unsigned")
    break;
  case 'v':
    CGEN_HANDLE_C_KEYWORD("void")
    CGEN_HANDLE_C_KEYWORD("volatile")
    break;
  case '_':
    CGEN_HANDLE_C_KEYWORD("_Alignas")
    CGEN_HANDLE_C_KEYWORD("_Alignof")
    CGEN_HANDLE_C_KEYWORD("_Atomic")
    CGEN_HANDLE_C_KEYWORD("_Bool")
    CGEN_HANDLE_C_KEYWORD("_Complex")
    CGEN_HANDLE_C_KEYWORD("_Decimal128")
    CGEN_HANDLE_C_KEYWORD("_Decimal32")
    CGEN_HANDLE_C_KEYWORD("_Decimal64")
    CGEN_HANDLE_C_KEYWORD("_Generic")
    CGEN_HANDLE_C_KEYWORD("_Imaginary")
    CGEN_HANDLE_C_KEYWORD("_Noreturn")
    CGEN_HANDLE_C_KEYWORD("_Static_assert")
    CGEN_HANDLE_C_KEYWORD("_Thread_local")
    break;
  default:
  }
emit:
  fprintf(output_file, "%.*s", len, str);
}

void cgen_emit_assign_rhs(struct ast_node *rhs) {
  switch (rhs->kind) {
  case AST_NODE_IDENT:
    cgen_emit_ident(rhs);
    break;
  case AST_NODE_INT_LITERAL:
  case AST_NODE_STRING_LITERAL:
  case AST_NODE_CHAR_LITERAL:
  case AST_NODE_BOOL_LITERAL:
  case AST_NODE_NULL_LITERAL:
    fprintf(output_file, "%.*s", rhs->string_data_len, rhs->string_data);
    break;
  case AST_NODE_ARRAY_LITERAL:
    cgen_emit_array_literal(rhs);
    break;
  case AST_NODE_RT_NEWPAIR:
    cgen_emit_newpair(rhs);
    break;
  case AST_NODE_CALL:
    cgen_emit_call(rhs);
    break;
  case AST_NODE_ARRAY_ELEM:
    cgen_emit_array_elem(rhs);
    break;
  case AST_NODE_PAIR_ELEM:
    fprintf(output_file, "(");
    cgen_emit_assign_rhs(ast_first_child(rhs));
    fprintf(output_file, ")->%s", rhs->token_id == TOK_FST ? "fst" : "snd");
    break;
  case AST_NODE_BINARY:
    fprintf(output_file, "(");
    cgen_emit_assign_rhs(ast_first_child(rhs));
    fprintf(output_file, " %.*s ", rhs->string_data_len, rhs->string_data);
    cgen_emit_assign_rhs(ast_nth_child(rhs, 1));
    fprintf(output_file, ")");
    break;
  case AST_NODE_UNARY:
    switch (rhs->token_id) {
    case TOK_LEN:
      fprintf(output_file, "$arrayLength(");
      cgen_emit_assign_rhs(ast_first_child(rhs));
      fprintf(output_file, ")");
      break;
    case TOK_EXCLAMATION_MARK:
      fprintf(output_file, "!");
      cgen_emit_assign_rhs(ast_first_child(rhs));
      break;
    case TOK_ORD:
      fprintf(output_file, "(Int)");
      cgen_emit_assign_rhs(ast_first_child(rhs));
      break;
    case TOK_CHR:
      fprintf(output_file, "(Char)");
      cgen_emit_assign_rhs(ast_first_child(rhs));
      break;
    case TOK_DASH:
      fprintf(output_file, "-");
      cgen_emit_assign_rhs(ast_first_child(rhs));
      break;
    }
    break;
  default:
  }
}

void cgen_emit_read(int ident_level, struct ast_node *node) {
  frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
  struct ast_node *loc = ast_first_child(node);
  if (loc->tindex == TINDEX_INT) {
    fprintf(output_file, "scanf(\" %%d\", &(");
  } else {
    fprintf(output_file, "scanf(\" %%c\", &(");
  }
  cgen_emit_assign_rhs(loc);
  fprintf(output_file, "));\n");
}

void cgen_emit_decl(int ident_level, struct ast_node *decl) {
  const char *type = cgen_get_type_name(type_from_ast(ast_first_child(decl)));
  struct ast_node *ident = ast_nth_child(decl, 1);
  frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
  fprintf(output_file, "%s ", type);
  cgen_emit_ident(ident);
  fprintf(output_file, " = ");
  cgen_emit_assign_rhs(ast_nth_child(decl, 2));
  fprintf(output_file, ";\n");
}

void cgen_emit_assignment(int ident_level, struct ast_node *decl) {
  struct ast_node *lhs = ast_first_child(decl);
  frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
  cgen_emit_assign_rhs(lhs);
  fprintf(output_file, " = ");
  cgen_emit_assign_rhs(ast_next_child(lhs));
  fprintf(output_file, ";\n");
}

void cgen_emit_rt_call(int ident_level, struct ast_node *rt_call) {
  struct ast_node *node = ast_first_child(rt_call);
  frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
  switch (rt_call->token_id) {
  case TOK_EXIT:
    fputs("exit((", output_file);
    cgen_emit_assign_rhs(ast_first_child(rt_call));
    fprintf(output_file, ") %% 256);\n");
    return;
  case TOK_PRINT:
  case TOK_PRINTLN:
    if (node->tindex == type_make_array(TINDEX_CHAR)) {
      fprintf(output_file, "$printCharArray(");
      cgen_emit_assign_rhs(node);
      fprintf(output_file,
              rt_call->token_id == TOK_PRINTLN ? ", true);" : ", false);\n");
      return;
    }
    fprintf(output_file, "printf(");
    switch (node->tindex) {
    case TINDEX_INT:
      fprintf(output_file, "\"%%d");
      break;
    case TINDEX_STRING:
      fprintf(output_file, "\"%%s");
      break;
    case TINDEX_BOOL:
      // Converting boolean to string is handled later
      fprintf(output_file, "\"%%s");
      break;
    case TINDEX_CHAR:
      fprintf(output_file, "\"%%c");
      break;
    default:
      fprintf(output_file, "\"%%r");
      break;
    }
    fprintf(output_file,
            rt_call->token_id == TOK_PRINTLN ? "\\n\", (" : "\", (");
    cgen_emit_assign_rhs(node);
    if (node->tindex == TINDEX_BOOL) {
      fprintf(output_file, ") ? \"true\" : \"false\");\n");
    } else {
      fprintf(output_file, "));\n");
    }
    break;
  case TOK_FREE: {
    struct type *type = types + node->tindex - TINDEX_CONSTRUCTOR_BASE;
    fprintf(output_file, "%s(", type->c_free_name);
    cgen_emit_assign_rhs(node);
    fprintf(output_file, ");\n");
    break;
  }
  default:
    __builtin_unreachable();
  }
}

void cgen_emit_scope(int ident_level, struct ast_node *scope) {
  struct ast_node *stmt = ast_first_child(scope);
  while (stmt != NULL) {
    switch (stmt->kind) {
    case AST_NODE_SCOPE:
      cgen_emit_line(ident_level, "{");
      cgen_emit_scope(ident_level + 1, stmt);
      cgen_emit_line(ident_level, "}");
      break;
    case AST_NODE_IF:
      frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
      fprintf(output_file, "if (");
      cgen_emit_assign_rhs(ast_first_child(stmt));
      fprintf(output_file, ") {\n");
      cgen_emit_scope(ident_level + 1, ast_nth_child(stmt, 1));
      frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
      fprintf(output_file, "} else {\n");
      cgen_emit_scope(ident_level + 1, ast_nth_child(stmt, 2));
      frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
      fprintf(output_file, "}\n");
      break;
    case AST_NODE_WHILE:
      frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
      fprintf(output_file, "while (");
      cgen_emit_assign_rhs(ast_first_child(stmt));
      fprintf(output_file, ") {\n");
      cgen_emit_scope(ident_level + 1, ast_nth_child(stmt, 1));
      frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
      fprintf(output_file, "}\n");
      break;
    case AST_NODE_RETURN:
      frepeat(output_file, CGEN_IDENT_SEQ, ident_level);
      fprintf(output_file, "return ");
      cgen_emit_assign_rhs(ast_first_child(stmt));
      fprintf(output_file, ";\n");
      cgen_emit_sep();
      break;
    case AST_NODE_DECL:
      cgen_emit_decl(ident_level, stmt);
      break;
    case AST_NODE_ASSIGNMENT:
      cgen_emit_assignment(ident_level, stmt);
      break;
    case AST_NODE_RT_READ:
      cgen_emit_read(ident_level, stmt);
      break;
    case AST_NODE_RT_CALL:
      cgen_emit_rt_call(ident_level, stmt);
      break;
    default:
    }
    stmt = ast_next_child(stmt);
  }
}

void cgen_emit_func_def(struct ast_node *function) {
  const char *return_type =
      cgen_get_type_name(type_from_ast(ast_first_child(function)));
  struct ast_node *ident = ast_nth_child(function, 1);
  struct ast_node *param_list = ast_next_child(ident);
  struct ast_node *scope = ast_next_child(param_list);

  fprintf(output_file, "%s $%.*s(", return_type, ident->string_data_len,
          ident->string_data);

  struct ast_node *param = ast_first_child(param_list);
  while (param != NULL) {
    struct ast_node *next_param = ast_next_child(param);
    const char *param_type =
        cgen_get_type_name(type_from_ast(ast_first_child(param)));
    struct ast_node *ident = ast_nth_child(param, 1);
    fprintf(output_file, "%s ", param_type);
    cgen_emit_ident(ident);
    if (next_param != NULL) {
      fprintf(output_file, ", ");
    }
    param = next_param;
  }
  fprintf(output_file, ") {\n");
  cgen_emit_scope(1, scope);
  fprintf(output_file, "}\n");
}

void cgen_pass(struct ast_node *program) {
  fputs(CGEN_PRELUDE, output_file);
  cgen_emit_sep();

  for (tindex_t i = 0; i < type_last_allocated_idx; ++i) {
    cgen_emit_typedef(types + i);
    cgen_emit_sep();
  }

  cgen_emit_func_decls();
  cgen_emit_sep();

  struct ast_node *node = ast_first_child(program);
  while (node->kind == AST_NODE_FUNC || node->kind == AST_NODE_EXTERN) {
    if (node->kind == AST_NODE_EXTERN) {
      node = ast_next_child(node);
      continue;
    }
    cgen_emit_func_def(node);
    cgen_emit_sep();
    node = ast_next_child(node);
  }

  fprintf(output_file, "int main() {\n");
  cgen_emit_scope(1, node);
  fprintf(output_file, "}\n");
}

int main(int argc, char const *argv[]) {
  if (argc != 2 && argc != 3) {
    fprintf(stderr, "usage: %s <source path> [<output path>]\n", argv[0]);
    return EXIT_MISC_ERROR;
  }

  source_path = argv[1];
  if (!verify_extension(source_path)) {
    fprintf(stderr, "error: source path should end with .wacc\n");
    return EXIT_MISC_ERROR;
  }

  if (argc == 3) {
    output_file = fopen(argv[2], "w");
    if (output_file == NULL) {
      fprintf(stderr,
              "error: can't open the output file \'%s\' for writing: %s \n",
              argv[2], strerror(errno));
      return EXIT_MISC_ERROR;
    }
#define OUTPUT_BUF_SIZE 0x100000
    char *buf = alloc_eternal(OUTPUT_BUF_SIZE, 16);
    setbuffer(output_file, buf, OUTPUT_BUF_SIZE);
  } else if (argc == 2) {
    output_file = stdout;
  }

  mmap_source();
  mmap_ast_nodes();
  mmap_types();
  mmap_functions();

  struct ast_node *ast = parse_program();
  check_returns_pass(ast);

  functions_pass(ast);
  sema_main_pass(ast);

  sema_assert_passed_checks();
  cgen_pass(ast);
}
