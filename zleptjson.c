#include "zleptjson.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef ZLEPT_PARSE_STACK_INIT_SIZE
#define ZLEPT_PARSE_STACK_INIT_SIZE 256
#endif
#ifndef ZLEPT_PARSE_STRINGIFY_INIT_SIZE
#define ZLEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define EXPECT(c, ch)         \
  do {                        \
    assert(*c->json == (ch)); \
    c->json++;                \
  } while (0)

#define PUTC(c, ch)                                     \
  do {                                                  \
    *(char*)zlept_context_push(c, sizeof(char)) = (ch); \
  } while (0)

#define PUTS(c, s, len)                         \
  do {                                          \
    memcpy(zlept_context_push(c, len), s, len); \
  } while (0)

typedef struct {
  const char* json;
  char* stack;
  size_t size, top;
} zlept_context;

static void* zlept_context_push(zlept_context* c, size_t size) {
  void* ret;
  assert(size > 0);
  if (c->top + size >= c->size) {
    if (c->size == 0) {
      c->size = ZLEPT_PARSE_STACK_INIT_SIZE;
    }
    while (c->top + size >= c->size) {
      c->size += c->size >> 1;
    }
    c->stack = (char*)realloc(c->stack, c->size);
  }
  ret = c->stack + c->top;
  c->top += size;
  return ret;
}

static void* zlept_context_pop(zlept_context* c, size_t size) {
  assert(c->top >= size);
  return c->stack + (c->top -= size);
}

#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')

static void zlept_parse_whitespace(zlept_context* c) {
  const char* p = c->json;
  while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r') {
    p++;
  }
  c->json = p;
}

static int lept_parse_literal(zlept_context* c, zlept_value* v,
                              zlept_type expect, const char* expected_json) {
  size_t i;
  EXPECT(c, *expected_json);
  for (i = 0; expected_json[i + 1]; i++) {
    if (c->json[i] != expected_json[i + 1]) {
      return ZLEPT_PARSE_INVALID_VALUE;
    }
  }
  c->json += i;
  v->type = expect;
  return ZLEPT_PARSE_OK;
}

static int zlept_parse_number(zlept_context* c, zlept_value* v) {
  const char* p = c->json;
  if (*p == '-') p++;
  if (*p == '0')
    p++;
  else {
    if (!ISDIGIT1TO9(*p)) return ZLEPT_PARSE_INVALID_VALUE;
    for (p++; ISDIGIT(*p); p++)
      ;
  }
  if (*p == '.') {
    p++;
    if (!ISDIGIT(*p)) return ZLEPT_PARSE_INVALID_VALUE;
    for (p++; ISDIGIT(*p); p++)
      ;
  }
  if (*p == 'e' || *p == 'E') {
    p++;
    if (*p == '+' || *p == '-') p++;
    if (!ISDIGIT(*p)) return ZLEPT_PARSE_INVALID_VALUE;
    for (p++; ISDIGIT(*p); p++)
      ;
  }
  errno = 0;
  v->u.n = strtod(c->json, NULL);
  if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)) {
    return ZLEPT_PARSE_NUMBER_TOO_BIG;
  }
  c->json = p;
  v->type = ZLEPT_NUMBER;
  return ZLEPT_PARSE_OK;
}

#define STRING_ERROR(ret) \
  do {                    \
    c->top = head;        \
    return ret;           \
  } while (0)

static const char* zlept_parse_hex4(const char* p, unsigned* u) {
  int i;
  *u = 0;
  for (i = 0; i < 4; i++) {
    char ch = *p++;
    *u <<= 4;
    if (ch >= '0' && ch <= '9')
      *u |= ch - '0';
    else if (ch >= 'A' && ch <= 'F')
      *u |= ch - 'A' + 10;
    else if (ch >= 'a' && ch <= 'f')
      *u |= ch - 'a' + 10;
    else
      return NULL;
  }
  return p;
}

static void zlept_encode_utf8(zlept_context* c, unsigned u) {
  if (u <= 0x007F)
    PUTC(c, u & 0x7F);
  else if (u <= 0x07FF) {
    PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
    PUTC(c, 0x80 | (u & 0x3F));
  } else if (u <= 0xFFFF) {
    PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
    PUTC(c, 0x80 | ((u >> 6) & 0x3F));
    PUTC(c, 0x80 | (u & 0x3F));
  } else {
    assert(u <= 0x10FFFF);
    PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
    PUTC(c, 0x80 | ((u >> 12) & 0x3F));
    PUTC(c, 0x80 | ((u >> 6) & 0x3F));
    PUTC(c, 0x80 | (u & 0x3F));
  }
}

int zlept_parse_string_raw(zlept_context* c, char** str, size_t* len) {
  size_t head = c->top;
  const char* p;
  unsigned u, u2;
  EXPECT(c, '\"');
  p = c->json;
  for (;;) {
    char ch = *p++;
    switch (ch) {
      case '\\':
        switch (*p++) {
          case '\"':
            PUTC(c, '\"');
            break;
          case '\\':
            PUTC(c, '\\');
            break;
          case '/':
            PUTC(c, '/');
            break;
          case 'b':
            PUTC(c, '\b');
            break;
          case 'f':
            PUTC(c, '\f');
            break;
          case 'n':
            PUTC(c, '\n');
            break;
          case 'r':
            PUTC(c, '\r');
            break;
          case 't':
            PUTC(c, '\t');
            break;
          case 'u':
            if (!(p = zlept_parse_hex4(p, &u)))
              STRING_ERROR(ZLEPT_PARSE_INVALID_UNICODE_HEX);
            if (u >= 0xD800 && u <= 0xDBFF) {
              if (*p++ != '\\') {
                STRING_ERROR(ZLEPT_PARSE_INVALID_UNICODE_SURROGATE);
              }
              if (*p++ != 'u') {
                STRING_ERROR(ZLEPT_PARSE_INVALID_UNICODE_SURROGATE);
              }
              if (!(p = zlept_parse_hex4(p, &u2)))
                STRING_ERROR(ZLEPT_PARSE_INVALID_UNICODE_HEX);
              if (u2 < 0xDC00 || u2 > 0xDFFF)
                STRING_ERROR(ZLEPT_PARSE_INVALID_UNICODE_SURROGATE);
              u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
            }
            zlept_encode_utf8(c, u);
            break;
          default:
            STRING_ERROR(ZLEPT_PARSE_INVALID_STRING_ESCAPE);
        };
        break;
      case '\"':
        *len = c->top - head;
        *str = zlept_context_pop(c, *len);
        c->json = p;
        return ZLEPT_PARSE_OK;
      case '\0':
        STRING_ERROR(ZLEPT_PARSE_MISS_QUOTATION_MARK);
      default:
        if ((unsigned char)ch < 0x20) {
          STRING_ERROR(ZLEPT_PARSE_INVALID_STRING_CHAR);
        }
        PUTC(c, ch);
    }
  }
}

static int zlept_parse_string(zlept_context* c, zlept_value* v) {
  int ret;
  char* str;
  size_t size;
  if ((ret = zlept_parse_string_raw(c, &str, &size)) == ZLEPT_PARSE_OK) {
    zlept_set_string(v, str, size);
  }
  return ret;
}

static int zlept_parse_value(zlept_context* c, zlept_value* v); /* 前向声明 */

static int zlept_parse_array(zlept_context* c, zlept_value* v) {
  size_t size = 0;
  int ret, i;
  EXPECT(c, '[');
  zlept_parse_whitespace(c);
  if (*c->json == ']') {
    c->json++;
    v->type = ZLEPT_ARRAY;
    v->u.a.e = NULL;
    v->u.a.size = 0;
    return ZLEPT_PARSE_OK;
  }
  for (;;) {
    zlept_value e;
    zlept_parse_whitespace(c);
    zlept_init(&e);
    if ((ret = zlept_parse_value(c, &e)) != ZLEPT_PARSE_OK) return ret;
    memcpy(zlept_context_push(c, sizeof(zlept_value)), &e, sizeof(zlept_value));
    size++;
    zlept_parse_whitespace(c);
    if (*c->json == ',') {
      c->json++;
    } else if (*c->json == ']') {
      c->json++;
      v->type = ZLEPT_ARRAY;
      v->u.a.size = size;
      size = size * sizeof(zlept_value);
      memcpy(v->u.a.e = malloc(size), zlept_context_pop(c, size), size);
      return ZLEPT_PARSE_OK;
    } else {
      ret = ZLEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
      break;
    }
  }
  for (i = 0; i < size; i++) {
    zlept_free((zlept_value*)zlept_context_pop(c, sizeof(zlept_value)));
  }
  return ret;
}

static int zlept_parse_object(zlept_context* c, zlept_value* v) {
  size_t size = 0;
  zlept_member m;
  int ret, i;
  EXPECT(c, '{');
  zlept_parse_whitespace(c);
  if (*c->json == '}') {
    c->json++;
    v->type = ZLEPT_OBJECT;
    v->u.o.m = NULL;
    v->u.o.size = 0;
    return ZLEPT_PARSE_OK;
  }
  m.k = NULL;
  m.klen = 0;
  for (;;) {
    char* str;
    zlept_init(&m.v);
    if (*c->json != '\"') {
      ret = ZLEPT_PARSE_MISS_KEY;
      break;
    }
    if ((ret = zlept_parse_string_raw(c, &str, &m.klen)) != ZLEPT_PARSE_OK)
      break;
    m.k = malloc(m.klen + 1);
    memcpy(m.k, str, m.klen);
    m.k[m.klen] = '\0';
    zlept_parse_whitespace(c);
    if (*c->json != ':') {
      ret = ZLEPT_PARSE_MISS_COLON;
      break;
    }
    c->json++;
    zlept_parse_whitespace(c);
    if ((ret = zlept_parse_value(c, &m.v)) != ZLEPT_PARSE_OK) break;
    memcpy(zlept_context_push(c, sizeof(zlept_member)), &m,
           sizeof(zlept_member));
    size++;
    m.k = NULL;
    zlept_parse_whitespace(c);
    if (*c->json == ',') {
      c->json++;
      zlept_parse_whitespace(c);
    } else if (*c->json == '}') {
      v->u.o.size = size;
      size *= sizeof(zlept_member);
      memcpy(v->u.o.m = malloc(size), zlept_context_pop(c, size), size);
      v->type = ZLEPT_OBJECT;
      c->json++;
      return ZLEPT_PARSE_OK;
    } else {
      ret = ZLEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
      break;
    }
  }
  free(m.k);
  for (i = 0; i < size; i++) {
    zlept_member* m = (zlept_member*)zlept_context_pop(c, sizeof(zlept_member));
    free(m->k);
    zlept_free(&m->v);
  }
  return ret;
}

static int zlept_parse_value(zlept_context* c, zlept_value* v) {
  switch (*c->json) {
    case 'n':
      return lept_parse_literal(c, v, ZLEPT_NULL, "null");
    case 't':
      return lept_parse_literal(c, v, ZLEPT_TRUE, "true");
    case 'f':
      return lept_parse_literal(c, v, ZLEPT_FALSE, "false");
    default:
      return zlept_parse_number(c, v);
    case '\"':
      return zlept_parse_string(c, v);
    case '[':
      return zlept_parse_array(c, v);
    case '{':
      return zlept_parse_object(c, v);
    case '\0':
      return ZLEPT_PARSE_EXPECT_VALUE;
  }
}

int zlept_parse(zlept_value* v, const char* json) {
  zlept_context c;
  int ret;
  assert(v != NULL);
  v->type = ZLEPT_NULL;
  c.json = json;
  c.stack = NULL;
  c.size = c.top = 0;
  zlept_init(v);
  zlept_parse_whitespace(&c);
  if ((ret = zlept_parse_value(&c, v)) == ZLEPT_PARSE_OK) {
    zlept_parse_whitespace(&c);
    if (*c.json != '\0') {
      v->type = ZLEPT_NULL;
      ret = ZLEPT_PARSE_ROOT_NOT_SINGULAR;
    }
  }
  assert(c.top == 0);
  free(c.stack);
  return ret;
}

static void zlept_stringify_string(zlept_context* c, const char* s, size_t len) {
  static const char hex_digits[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  size_t i, size;
  char *head, *p;
  assert(s != NULL);
  p = head = zlept_context_push(c, size = len * 6 + 2); /* "\u00xx..." */
  *p++ = '\"';
  for (i = 0; i < len; i++) {
    unsigned char ch = (unsigned char)s[i];
    switch (ch) {
      case '\"':
        *p++ = '\\';
        *p++ = '\"';
        break;
      case '\\':
        *p++ = '\\';
        *p++ = '\\';
        break;
      case '\b':
        *p++ = '\\';
        *p++ = 'b';
        break;
      case '\f':
        *p++ = '\\';
        *p++ = 'f';
        break;
      case '\n':
        *p++ = '\\';
        *p++ = 'n';
        break;
      case '\r':
        *p++ = '\\';
        *p++ = 'r';
        break;
      case '\t':
        *p++ = '\\';
        *p++ = 't';
        break;
      default:
        if (ch < 0x20) {
          *p++ = '\\';
          *p++ = 'u';
          *p++ = '0';
          *p++ = '0';
          *p++ = hex_digits[ch >> 4];
          *p++ = hex_digits[ch & 15];
        } else
          *p++ = s[i];
    }
  }
  *p++ = '\"';
  c->top -= size - (p - head);
}

static void zlept_stringify_value(zlept_context* c, const zlept_value* v) {
  size_t i;
  switch (v->type) {
    case ZLEPT_NULL:
      PUTS(c, "null", 4);
      break;
    case ZLEPT_FALSE:
      PUTS(c, "false", 5);
      break;
    case ZLEPT_TRUE:
      PUTS(c, "true", 4);
      break;
    case ZLEPT_NUMBER: 
      c->top -= 32 - sprintf(zlept_context_push(c, 32), "%.17g", v->u.n);
      break;
    case ZLEPT_STRING:
      zlept_stringify_string(c, v->u.s.s, v->u.s.len);
      break;
    case ZLEPT_ARRAY:
      PUTC(c, '[');
      for(i = 0; i < v->u.a.size; i++){
        if (i > 0) 
          PUTC(c, ',');
        zlept_stringify_value(c, &v->u.a.e[i]);
      }
      PUTC(c, ']');
      break;
    case ZLEPT_OBJECT:
      PUTC(c, '{');
      for(i = 0; i < v->u.o.size; i++){
        if(i > 0)
          PUTC(c, ',');
        zlept_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
        PUTC(c, ':');
        zlept_stringify_value(c, &v->u.o.m[i].v);
      }
      PUTC(c, '}');
      break;
    default:
      break;
  }
}

char* zlept_stringify(const zlept_value* v, size_t* length) {
  zlept_context c;
  assert(v != NULL);
  c.stack = (char*)malloc(ZLEPT_PARSE_STRINGIFY_INIT_SIZE);
  c.top = 0;
  zlept_stringify_value(&c, v);
  if (length) *length = c.top;
  PUTC(&c, '\0');
  return c.stack;
}

zlept_type zlept_get_type(const zlept_value* v) {
  assert(v != NULL);
  return v->type;
}

void zlept_free(zlept_value* v) {
  size_t i;
  assert(v != NULL);
  switch (v->type) {
    case ZLEPT_STRING:
      free(v->u.s.s);
      break;
    case ZLEPT_ARRAY:
      for (i = 0; i < v->u.a.size; i++) zlept_free(v->u.a.e);
      break;
    case ZLEPT_OBJECT:
      for (i = 0; i < v->u.o.size; i++) {
        free(v->u.o.m[i].k);
        zlept_free(&v->u.o.m[i].v);
      }
      free(v->u.o.m);
      break;
    default:
      break;
  }
  v->type = ZLEPT_NULL;
}

int zlept_get_boolean(const zlept_value* v) {
  assert(v != NULL && (v->type == ZLEPT_TRUE || v->type == ZLEPT_FALSE));
  return v->type == ZLEPT_TRUE;
}

void zlept_set_boolean(zlept_value* v, int b) {
  zlept_free(v);
  v->type = b ? ZLEPT_TRUE : ZLEPT_FALSE;
}

double zlept_get_number(const zlept_value* v) {
  assert(v != NULL && v->type == ZLEPT_NUMBER);
  return v->u.n;
}

void zlept_set_number(zlept_value* v, double n) {
  zlept_free(v);
  v->u.n = n;
  v->type = ZLEPT_NUMBER;
}

const char* zlept_get_string(const zlept_value* v) {
  assert(v != NULL && v->type == ZLEPT_STRING);
  return v->u.s.s;
}

size_t zlept_get_string_length(const zlept_value* v) {
  assert(v != NULL && v->type == ZLEPT_STRING);
  return v->u.s.len;
}

void zlept_set_string(zlept_value* v, const char* s, size_t len) {
  assert(s != NULL || len == 0);
  zlept_free(v);
  v->u.s.s = (char*)malloc(len + 1);
  memcpy(v->u.s.s, s, len);
  v->u.s.s[len] = '\0';
  v->u.s.len = len;
  v->type = ZLEPT_STRING;
}

size_t zlept_get_array_size(const zlept_value* v) {
  assert(v != NULL && v->type == ZLEPT_ARRAY);
  return v->u.a.size;
}

zlept_value* zlept_get_array_element(const zlept_value* v, size_t index) {
  assert(v != NULL && v->type == ZLEPT_ARRAY);
  assert(index < v->u.a.size);
  return &v->u.a.e[index];
}

size_t zlept_get_object_size(const zlept_value* v) {
  assert(v != NULL && v->type == ZLEPT_OBJECT);
  return v->u.o.size;
}

const char* zlept_get_object_key(const zlept_value* v, size_t index) {
  assert(v != NULL && v->type == ZLEPT_OBJECT);
  assert(index < v->u.o.size);
  return v->u.o.m[index].k;
}

size_t zlept_get_object_key_length(const zlept_value* v, size_t index) {
  assert(v != NULL && v->type == ZLEPT_OBJECT);
  assert(index < v->u.o.size);
  return v->u.o.m[index].klen;
}

zlept_value* zlept_get_object_value(const zlept_value* v, size_t index) {
  return &v->u.o.m[index].v;
}
