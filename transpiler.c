#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
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

void *alloc(size_t size) {
  void *res = malloc(size);
  if (res == NULL) {
    fprintf(stderr, "internal error: allocation failure\n");
    exit(EXIT_MISC_ERROR);
  }
  return res;
}

struct pos {
  size_t line;
  size_t column;
};

void to_pos(size_t raw, struct pos *buf) {
  size_t newlines = 0;
  size_t last_newline = 0;
  for (size_t i = 0; i < raw; ++i) {
    if (source[i] == '\n') {
      last_newline = i;
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
  else if (strlen(_keyword) == cur - source_pos &&                             \
           memcmp(source + source_pos, _keyword, cur - source_pos) == 0) {     \
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

      if (false) {
      }
      TOK_HANDLE_KEYWORD(TOK_BEGIN, "begin")
      TOK_HANDLE_KEYWORD(TOK_END, "end")
      TOK_HANDLE_KEYWORD(TOK_IS, "is")
      TOK_HANDLE_KEYWORD(TOK_SKIP, "skip")
      TOK_HANDLE_KEYWORD(TOK_PRINTLN, "println")
      TOK_HANDLE_KEYWORD(TOK_PRINT, "print")
      TOK_HANDLE_KEYWORD(TOK_READ, "read")
      TOK_HANDLE_KEYWORD(TOK_FREE, "free")
      TOK_HANDLE_KEYWORD(TOK_RETURN, "return")
      TOK_HANDLE_KEYWORD(TOK_EXIT, "exit")
      TOK_HANDLE_KEYWORD(TOK_IF, "if")
      TOK_HANDLE_KEYWORD(TOK_THEN, "then")
      TOK_HANDLE_KEYWORD(TOK_ELSE, "else")
      TOK_HANDLE_KEYWORD(TOK_FI, "fi")
      TOK_HANDLE_KEYWORD(TOK_WHILE, "while")
      TOK_HANDLE_KEYWORD(TOK_DONE, "done")
      TOK_HANDLE_KEYWORD(TOK_DO, "do")
      TOK_HANDLE_KEYWORD(TOK_NEWPAIR, "newpair")
      TOK_HANDLE_KEYWORD(TOK_CALL, "call")
      TOK_HANDLE_KEYWORD(TOK_FST, "fst")
      TOK_HANDLE_KEYWORD(TOK_SND, "snd")
      TOK_HANDLE_KEYWORD(TOK_INT, "int")
      TOK_HANDLE_KEYWORD(TOK_BOOL, "bool")
      TOK_HANDLE_KEYWORD(TOK_CHAR, "char")
      TOK_HANDLE_KEYWORD(TOK_STRING, "string")
      TOK_HANDLE_KEYWORD(TOK_PAIR, "pair")
      TOK_HANDLE_KEYWORD(TOK_LEN, "len")
      TOK_HANDLE_KEYWORD(TOK_ORD, "ord")
      TOK_HANDLE_KEYWORD(TOK_CHR, "chr")
      TOK_HANDLE_KEYWORD(TOK_NULL, "null")
      TOK_HANDLE_KEYWORD(TOK_BOOL_LITERAL, "true")
      TOK_HANDLE_KEYWORD(TOK_BOOL_LITERAL, "false")

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
          "error at %s:%zu:%zu: unexpected token (expected %s, got \"%.*s\")\n",
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

struct ast_node {
  const char *string_data;
  int string_data_len;
  int next_child;
  int first_child;
  enum {
    AST_NODE_PROGRAM,        // <no tag> function* statement
    AST_NODE_FUNC,           // <no tag> type name param_list scope
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
    AST_NODE_NEWPAIR,        // <no tag> expr expr
    AST_NODE_CALL,           // <function name> expr*
    AST_NODE_INT,            // <no tag> [no children]
    AST_NODE_BOOL,           // <no tag> [no children]
    AST_NODE_CHAR,           // <no tag> [no children]
    AST_NODE_STRING,         // <no tag> [no children]
    AST_NODE_PAIRPTR,        // <"null"> [no children]
    AST_NODE_ARRAY,          // <no tag> type
    AST_NODE_PAIR,           // <no tag> type type (not a pair in both cases)
    AST_NODE_INT_LITERAL,    // <int literal> [no children]
    AST_NODE_BOOL_LITERAL,   // <bool literal> [no children]
    AST_NODE_CHAR_LITERAL,   // <char literal> [no children]
    AST_NODE_STRING_LITERAL, // <string literal> [no children]
    AST_NODE_PAIR_LITERAL,   // <pair literal> [no children]
    AST_NODE_UNARY,          // <unary operator used> expr
    AST_NODE_BINARY,         // <binary operator used> expr
  } kind;
  int token_id; // set for operators
  int type_id;  // set for expressions
};

#define AST_NODES_MAX 16777216

struct ast_node *ast_nodes;

struct ast_node *ast_first_child(struct ast_node *cur) {
  if (cur->first_child == EXIT_SYNTAX_ERROR) {
    return NULL;
  }
  return ast_nodes + cur->first_child;
}

struct ast_node *ast_next_child(struct ast_node *cur) {
  if (cur->next_child == EXIT_SYNTAX_ERROR) {
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

void ast_set_cstr(struct ast_node *node, const char *str) {
  ast_set_tag(node, str, strlen(str));
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
  res->first_child = EXIT_SYNTAX_ERROR;
  res->next_child = EXIT_SYNTAX_ERROR;
  res->string_data = NULL;
  res->string_data_len = 0;
  return res;
}

struct ast_node *ast_alloc_node_tok(int kind, struct tok *tok) {
  struct ast_node *res = ast_alloc_node(kind);
  res->string_data = tok->tok_start;
  res->string_data_len = tok->tok_size;
  return res;
}

void repeat(const char *str, int times) {
  for (int i = 0; i < times; ++i) {
    fputs(str, stderr);
  }
}

void ast_dump(struct ast_node *node, int ident_lvl) {
  if (ident_lvl != 0) {
    repeat("  ", ident_lvl - 1);
    fputs("- ", stderr);
  }
  fprintf(stderr, "%d < %.*s >\n", node->kind, node->string_data_len,
          node->string_data);
  struct ast_node *child = ast_first_child(node);
  while (child != NULL) {
    ast_dump(child, ident_lvl + 1);
    child = ast_next_child(child);
  }
}

struct ast_node *parse_type();

struct ast_node *parse_pair_type_component() {
  struct tok tok;
  tok_peek_token(&tok);
  if (tok.tok_kind == TOK_PAIR) {
    tok_poll_token(&tok);
    struct ast_node *ptr = ast_alloc_node(AST_NODE_PAIRPTR);
    ast_set_cstr(ptr, "pairptr");
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
    res = ast_alloc_node_tok(AST_NODE_INT, &tok);
    break;
  case TOK_BOOL:
    res = ast_alloc_node_tok(AST_NODE_BOOL, &tok);
    break;
  case TOK_STRING:
    res = ast_alloc_node_tok(AST_NODE_STRING, &tok);
    break;
  case TOK_CHAR:
    res = ast_alloc_node_tok(AST_NODE_CHAR, &tok);
    break;
  case TOK_PAIR: {
    res = ast_alloc_node(AST_NODE_PAIR);
    ast_set_cstr(res, "pair");
    struct ast_node *last_child = NULL;

    tok_expect_token(TOK_LPAREN, "\"(\"");
    ast_add_child(res, parse_pair_type_component(), &last_child);
    tok_expect_token(TOK_COMMA, "\",\"");
    ast_add_child(res, parse_pair_type_component(), &last_child);
    tok_expect_token(TOK_RPAREN, "\")\"");
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
    tok_expect_token(TOK_RBRACKET, "\"]\"");
    struct ast_node *arr = ast_alloc_node(AST_NODE_ARRAY);
    ast_set_cstr(arr, "array");
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
      ast_set_cstr(node, "[]");
      ast_add_child(node, ident, &last_child);
    }
    tok_poll_token(&tok);
    struct ast_node *expr = parse_expr();
    ast_add_child(node, expr, &last_child);
    tok_expect_token(TOK_RBRACKET, "\"]\"");
  }
  return node;
}

struct ast_node *parse_expr0() {
  struct tok tok;
  struct ast_node *res;
  tok_peek_token_no_eof(&tok, "primary expression");

  bool negate_integer_literal = false;

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
        ast_set_tag(res, tok.tok_start, tok.tok_size);
        ast_add_first_child(res, parse_expr0());
        break;
      }
    }
    negate_integer_literal = tok.tok_kind == TOK_DASH;
  }
  // fallthrough
  case TOK_INT_LITERAL:
    tok_poll_token(&tok);
    res = ast_alloc_node(AST_NODE_INT_LITERAL);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    // should be safe, since after the token there could only be a null
    // character or some non-numeric character
    long value = strtol(tok.tok_start, NULL, 10);
    if (value > ((long)INT_MAX + 1) ||
        (value > INT_MAX && !negate_integer_literal)) {
      struct pos pos;
      to_pos(tok.tok_start - source, &pos);
      fprintf(stderr,
              "error at %s:%zu:%zu: integer constant \"%.*s\" outside of the "
              "valid range\n",
              source_path, pos.line, pos.column, tok.tok_size, tok.tok_start);
      exit(EXIT_SYNTAX_ERROR);
    }
    break;
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
    res = ast_alloc_node(AST_NODE_PAIR_LITERAL);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    break;
  case TOK_LPAREN:
    tok_poll_token(&tok);
    res = parse_expr();
    tok_expect_token(TOK_RPAREN, "\")\"");
    break;
  case TOK_IDENT:
    res = parse_array_elem_or_ident(TOK_IDENT);
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    break;
  case TOK_EXCLAMATION_MARK:
  case TOK_LEN:
  case TOK_ORD:
  case TOK_CHR:
    tok_poll_token(&tok);
    res = ast_alloc_node(AST_NODE_UNARY);
    res->token_id = tok.tok_kind;
    ast_set_tag(res, tok.tok_start, tok.tok_size);
    ast_add_first_child(res, parse_expr0());
    break;
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
  ast_set_cstr(res, "array_literal");

  struct ast_node *last_child = NULL;
  tok_expect_token(TOK_LBRACKET, "\"[\"");

  struct tok tok;
  tok_peek_token_no_eof(&tok, "expression or \"]\"");
  if (tok.tok_kind == TOK_RBRACKET) {
    tok_poll_token(&tok);
    return res;
  }

  while (true) {
    ast_add_child(res, parse_expr(), &last_child);

    tok_peek_token_no_eof(&tok, "\",\" or \"]\"");
    if (tok.tok_kind == TOK_RBRACKET) {
      tok_poll_token(&tok);
      return res;
    }
    tok_expect_token(TOK_COMMA, "\",\" or \"]\"");
  }

  return res;
}

struct ast_node *parse_newpair() {
  struct ast_node *res = ast_alloc_node(AST_NODE_NEWPAIR);
  tok_expect_token(TOK_NEWPAIR, "newpair");
  tok_expect_token(TOK_LPAREN, "\"(\"");
  struct ast_node *left = parse_expr();
  tok_expect_token(TOK_COMMA, "\",\"");
  struct ast_node *right = parse_expr();
  tok_expect_token(TOK_RPAREN, "\")\"");
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
  return node;
}

struct ast_node *parse_call() {
  struct tok tok;
  tok_expect_token(TOK_CALL, "call");
  tok_extract_of_type(&tok, TOK_IDENT, "identifier");
  tok_expect_token(TOK_LPAREN, "\"(\"");

  struct ast_node *node = ast_alloc_node(AST_NODE_CALL);
  struct ast_node *last_child = NULL;
  ast_set_tag(node, tok.tok_start, tok.tok_size);

  tok_peek_token_no_eof(&tok, "\")\" or expression");
  if (tok.tok_kind == TOK_RPAREN) {
    tok_poll_token(&tok);
    return node;
  }

  while (true) {
    struct ast_node *param = parse_expr();
    ast_add_child(node, param, &last_child);
    tok_poll_token_no_eof(&tok, "\",\" or \")\"");
    if (tok.tok_kind == TOK_RPAREN) {
      return node;
    } else if (tok.tok_kind == TOK_COMMA) {
      continue;
    }
    tok_report_unexpected(&tok, "\",\" or \")\"");
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
  tok_expect_token(TOK_ASSIGN, "\"=\"");
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
  ast_set_cstr(result, "assignment");

  struct ast_node *lhs = parse_assign_lhs();
  tok_expect_token(TOK_ASSIGN, "\"=\"");
  struct ast_node *rhs = parse_assign_rhs();
  ast_add_first_child(result, lhs);
  ast_add_next_child(lhs, rhs);
  return result;
}

struct ast_node *parse_scope();

struct ast_node *parse_explicit_scope() {
  struct tok tok;
  tok_extract_of_type(&tok, TOK_BEGIN, "begin");
  struct ast_node *res = parse_scope(TOK_END, "\";\" or end");
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
  struct ast_node *theng = parse_scope(TOK_ELSE, "\";\" or else");
  tok_expect_token(TOK_ELSE, "else");
  struct ast_node *elseg = parse_scope(TOK_FI, "\";\" or fi");
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
  struct ast_node *stmt = parse_scope(TOK_DONE, "\";\" or done");
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

// Do not forget to prepend "\";\"" to the term_expected_string, otherwise user
// will be confused
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
  tok_expect_token(TOK_SEMICOLON, "\";\" or end");

  parse_scope_in(res, &last_child, TOK_END, "\";\" or end");
  return res;
}

struct ast_node *parse_parameter_list() {
  struct ast_node *result = ast_alloc_node(AST_NODE_PARAM_LIST);
  ast_set_cstr(result, "paramlist");
  struct ast_node *last_child = NULL;
  tok_expect_token(TOK_LPAREN, "\"(\"");

  struct tok tok;
  tok_peek_token_no_eof(&tok, "\")\" or parameter definition");
  if (tok.tok_kind == TOK_RPAREN) {
    tok_poll_token(&tok);
    return result;
  }

  while (true) {
    struct ast_node *type = parse_type();
    struct ast_node *name = parse_ident();
    struct ast_node *param = ast_alloc_node(AST_NODE_PARAM);
    ast_set_cstr(param, "param");
    ast_add_first_child(param, type);
    ast_add_next_child(type, name);
    ast_add_child(result, param, &last_child);

    tok_peek_token_no_eof(&tok, "\",\" or \")\"");
    if (tok.tok_kind == TOK_RPAREN) {
      tok_poll_token(&tok);
      return result;
    }
    tok_expect_token(TOK_COMMA, "\",\" or \")\"");
  }

  return result;
}

struct ast_node *parse_function_tail(struct ast_node *type,
                                     struct ast_node *ident) {
  struct ast_node *function = ast_alloc_node(AST_NODE_FUNC);
  ast_set_cstr(function, "function");
  struct ast_node *params = parse_parameter_list();
  tok_expect_token(TOK_IS, "is");
  struct ast_node *stmt = parse_scope(TOK_END, "\";\" or end");
  tok_expect_token(TOK_END, "end");

  ast_add_first_child(function, type);
  ast_add_next_child(type, ident);
  ast_add_next_child(ident, params);
  ast_add_next_child(params, stmt);
  return function;
}

struct ast_node *parse_program() {
  tok_expect_token(TOK_BEGIN, "begin");
  struct ast_node *res = ast_alloc_node(AST_NODE_PROGRAM);
  struct ast_node *cur_child = NULL;
  ast_set_cstr(res, "program");

  while (parse_on_type()) {
    struct ast_node *type = parse_type();
    struct ast_node *ident = parse_ident();

    struct tok tok;
    tok_peek_token_no_eof(&tok, "\"=\" or \"(\"");
    if (tok.tok_kind == TOK_ASSIGN) {
      ast_add_child(res, parse_scope_tailing_decl(type, ident), &cur_child);
      tok_expect_token(TOK_END, "end");
      return res;
    }
    ast_add_child(res, parse_function_tail(type, ident), &cur_child);
  }

  struct ast_node *statement = parse_scope(TOK_END, "\";\" or end");
  ast_add_child(res, statement, &cur_child);
  tok_expect_token(TOK_END, "end");

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
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                   EXIT_SYNTAX_ERROR, 0);
  if (ast_nodes == MAP_FAILED) {
    perror("internal error: failed to map ast nodes pool");
    exit(EXIT_MISC_ERROR);
  }
}

void mmap_source() {
  int fd = open(source_path, O_RDONLY);
  if (fd < 0) {
    perror("error: failed to open the source file");
    exit(EXIT_MISC_ERROR);
  }

  struct stat source_stat;
  if (fstat(fd, &source_stat) != 0) {
    perror("error: failed to get source file size");
    exit(EXIT_MISC_ERROR);
  }
  source_size = source_stat.st_size;

  source = mmap(NULL, source_size, PROT_READ, MAP_PRIVATE, fd, 0);
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

void report_sema_error_at_ast_node(struct ast_node *node, const char *fmt,
                                   ...) {
  va_list args;
  sema_checks_passed = false;
  va_start(args, fmt);
  report_at_ast_node(node, "error", fmt, args);
  va_end(args);
}

void sema_assert_passed_checks() {
  if (!sema_checks_passed) {
    exit(EXIT_SEMANTIC_ERROR);
  }
}

void check_no_returns_pass(struct ast_node *stmt) {
  switch (stmt->kind) {
  case AST_NODE_RETURN:
    report_sema_error_at_ast_node(stmt,
                                  "attempt to return from the main program");
    break;
  case AST_NODE_IF: {
    struct ast_node *theng = ast_next_child(ast_first_child(stmt));
    struct ast_node *elseg = ast_next_child(theng);
    check_no_returns_pass(theng);
    check_no_returns_pass(elseg);
  } break;
  case AST_NODE_WHILE: {
    struct ast_node *body = ast_next_child(ast_first_child(stmt));
    check_no_returns_pass(body);
  } break;
  case AST_NODE_SCOPE: {
    struct ast_node *child = ast_first_child(stmt);
    while (child != NULL) {
      check_no_returns_pass(child);
      child = ast_next_child(child);
    }
  } break;
  default:
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
  while (child->kind == AST_NODE_FUNC) {
    struct ast_node *scope = ast_nth_child(child, 3);
    check_scope_returns(scope);
    child = ast_next_child(child);
  }
  check_no_returns_pass(child);
}

bool verify_extension(const char *path) {
  size_t len = strlen(path);
  size_t extension_len = strlen(WACC_EXTENSION);
  return memcmp(path + len - extension_len, WACC_EXTENSION, extension_len) == 0;
}

const char *replace_wacc_extension(const char *path) {
  size_t len = strlen(path);
  size_t wacc_extension_len = strlen(WACC_EXTENSION);
  size_t c_extension_len = strlen(C_EXTENSION);
  size_t new_len = len - wacc_extension_len + c_extension_len;

  char *res = alloc(new_len + 1);
  memcpy(res, path, len - wacc_extension_len);
  memcpy(res + (len - wacc_extension_len), C_EXTENSION, c_extension_len);
  res[new_len] = '\0';
  return res;
}

int main(int argc, char const *argv[]) {
  if (argc != 2 && argc != 3) {
    fprintf(stderr, "usage: %s <source path> [<output path>]\n", argv[0]);
    return EXIT_SYNTAX_ERROR;
  }

  source_path = argv[1];
  if (!verify_extension(source_path)) {
    fprintf(stderr, "error: source path should end with .wacc\n");
    return EXIT_SYNTAX_ERROR;
  }

  const char *output_path = argv[2];
  if (argc == 2) {
    output_path = replace_wacc_extension(source_path);
  }
  (void)output_path;

  mmap_source();
  mmap_ast_nodes();

  struct ast_node *ast = parse_program();
  check_returns_pass(ast);

  sema_assert_passed_checks();
  ast_dump(ast, 0);
}
