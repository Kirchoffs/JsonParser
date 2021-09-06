#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL, strtod() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <string.h>  /* memcpy() */
#include <stdio.h>

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif


#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch) do { assert(*c->json == (ch)); c->json++; } while (0)
#define PUTC(c, ch)         do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while (0)
#define PUTS(c, s, len)     memcpy(lept_context_push(c, len), s, len)

#define LEPT_KEY_NOT_EXIST ((size_t) -1)

static int lept_parse_value(lept_context*, lept_value*);

static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type) {
    EXPECT(c, literal[0]);
    size_t i;
    for (i = 0; literal[i+1]; i++) {
        if (c->json[i] != literal[i+1]) {
            return LEPT_PARSE_INVALID_VALUE;
        }
    }
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int is_digit(char ch) {
    return ch >= '0' && ch <= '9';
}

static int is_digit_one_to_nine(char ch) {
    return ch >= '1' && ch <= '9';
}

/*
 * number = [ "-" ] int [ frac ] [ exp ]
 * int = "0" / digit1-9 *digit
 * frac = "." +digit
 * exp = ("e" / "E") ["-" / "+"] +digit
 */
static int lept_parse_number(lept_context* c, lept_value* v) {
    const char* p = c->json;

    if (*p == '-') {
        p++;
    }

    if (*p == '0') {
        p++;
    } else {
        if (!is_digit_one_to_nine(*p)) {
            return LEPT_PARSE_INVALID_VALUE;
        }
        while (is_digit(*p)) {
            p++;
        }
    }

    if (*p == '.') {
        p++;
        if (!is_digit(*p)) {
            return LEPT_PARSE_INVALID_VALUE;
        }
        while (is_digit(*p)) {
            p++;
        }
    }

    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') {
            p++;
        }
        if (!is_digit(*p)) {
            return LEPT_PARSE_INVALID_VALUE;
        }
        while (is_digit(*p)) {
            p++;
        }
    }

    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
        return LEPT_PARSE_NUMBER_TOO_BIG;
    v->type = LEPT_NUMBER;
    c->json = p;
    return LEPT_PARSE_OK;
}

const char* lept_get_string(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.s.s = (char*) malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}

size_t lept_get_string_length(const lept_value* v) {
    return v->u.s.len;
}

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b) {
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

static void* lept_context_push(lept_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;  /* c->size * 1.5 */
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
    assert(c->top >= size);
    c->top -= size;
    return c->stack + c->top;
}

static const char* lept_parse_hex4(const char* p, unsigned* u) {
    *u = 0;
    int i;
    for (i = 0; i < 4; i++) {
        *u <<= 4;
        char ch = *p++;
        if (ch >= '0' && ch <= '9') {
            *u |= ch - '0';
        } else if (ch >= 'A' && ch <= 'F') {
            *u |= ch - 'A' + 10;
        } else if (ch >= 'a' && ch <= 'f') {
            *u |= ch - 'a' + 10;
        } else {
            return NULL;
        }
    }
    
    return p;
}

#define PUTC(c, ch) do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while (0)

static void lept_encode_utf8(lept_context* c, unsigned u) {
    if (u <= 0x7F) {
        PUTC(c, u & 0x7F);
    } else if (u <= 0x07FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0x1F));
        PUTC(c, 0x80 | (u & 0x3F));
    } else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0x0F));
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));
        PUTC(c, 0x80 | (u & 0x3F));
    } else {
        PUTC(c, 0xF0 | ((u >> 18) & 0x0F));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));
        PUTC(c, 0x80 | (u & 0x3F));
    }
}

static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
    unsigned u;
    size_t head = c->top;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\\':
                switch(*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/'); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = lept_parse_hex4(p, &u))) {
                            c->top = head;
                            return LEPT_PARSE_INVALID_UNICODE_HEX;
                        }
                        if (u >= 0xD800 && u <= 0xDBFF) {
                            if (*p++ != '\\') {
                                c->top = head;
                                return LEPT_PARSE_INVALID_UNICODE_SURROGATE;
                            }
                            if (*p++ != 'u') {
                                c->top = head;
                                return LEPT_PARSE_INVALID_UNICODE_SURROGATE;
                            }

                            unsigned u_surrogate = 0;
                            if (!(p = lept_parse_hex4(p, &u_surrogate))) {
                                c->top = head;
                                return LEPT_PARSE_INVALID_UNICODE_HEX;
                            }

                            if (u_surrogate < 0xDC00 || u_surrogate > 0xDFFF) {
                                c->top = head;
                                return LEPT_PARSE_INVALID_UNICODE_SURROGATE;
                            }

                            u = (((u - 0xD800) << 10) | (u_surrogate - 0xDC00)) + 0x10000;
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        c->top = head;
                        return LEPT_PARSE_INVALID_STRING_ESCAPE;
                }
                break;
            case '\"':
                *len = c->top - head;
                // If raw str is just "", then c->stack may never get allocated.
                // then c->stack is NULL
                *str = lept_context_pop(c, *len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                c->top = head;
                return LEPT_PARSE_MISS_QUOTATION_MARK;
            default:
                if ((unsigned char)ch < 0x20) {
                    c->top = head;
                    return LEPT_PARSE_INVALID_STRING_CHAR;
                }
                PUTC(c, ch);
        }
    }
}

static int lept_parse_string(lept_context* c, lept_value* v) {
    int ret;
    char* s;
    size_t len;
    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK)
        lept_set_string(v, s, len);
    return ret;
}

void lept_set_array(lept_value* v, size_t capacity) {
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_ARRAY;
    v->u.a.size = 0;
    v->u.a.capacity = capacity;
    v->u.a.e = capacity > 0 ? (lept_value*) malloc(capacity * sizeof(lept_value)) : NULL;
}

static int lept_parse_array(lept_context* c, lept_value* v) {
    size_t size = 0;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);

    // empty array
    if (*(c->json) == ']') {
        c->json++;
        lept_set_array(v, 0);
        return LEPT_PARSE_OK;
    }

    for(;;) {
        lept_value e;
        lept_init(&e);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK) {
            return ret;
        }
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;
        lept_parse_whitespace(c);
        if (*(c->json) == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else if (*(c->json) == ']') {
            c->json++;
            lept_set_array(v, size);
            v->u.a.size = size;
            memcpy(v->u.a.e, lept_context_pop(c, size * sizeof(lept_value)), size * sizeof(lept_value));
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }

    size_t i;
    for (i = 0; i < size; i++) {
        lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
    }

    return ret;
}

static int lept_parse_object(lept_context* c, lept_value* v) {
    size_t size;
    lept_member m;
    int ret;
    EXPECT(c, '{');
    lept_parse_whitespace(c);

    // empty object
    if (*(c->json) == '}') {
        c->json++;
        v->type = LEPT_OBJECT;
        v->u.o.m = 0;
        v->u.o.size = 0;
        return LEPT_PARSE_OK;
    }

    m.k = NULL;
    size = 0;
    for (;;) {
        char* str;
        lept_init(&m.v);

        // parse key to m.k, m.klen
        if (*(c->json) != '"') {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }

        if ((ret = lept_parse_string_raw(c, &str, &m.klen)) != LEPT_PARSE_OK) {
            break;
        }

        memcpy(m.k = (char*)malloc(sizeof(m.klen + 1)), str, m.klen);
        m.k[m.klen] = '\0';

        // parse colon
        lept_parse_whitespace(c);

        if (*c->json != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        lept_parse_whitespace(c);

        // parse value
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK) {
            break;
        }

        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.k = NULL;
        lept_parse_whitespace(c);

        if (*(c->json) == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else if (*(c->json) == '}') {
            c->json++;
            lept_set_object(v, size);
            v->u.o.size = size;
            memcpy(v->u.o.m, lept_context_pop(c, size * sizeof(lept_member)), size * sizeof(lept_member));
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }

    free(m.k);

    for (int i = 0; i < size; i++) {
        lept_member* tmp = (lept_member*)lept_context_pop(c, sizeof(lept_member));
        free(tmp->k);
        lept_free(&tmp->v);
    }

    v->type = LEPT_NULL;
    return ret;
}

/*
 * JSON-text = ws value ws
 * ws = spaces / tabs / LF / CR
 * value = null / false / true
 */
static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 'n': return lept_parse_literal(c, v, "null", LEPT_NULL);
        case 't': return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f': return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
        case '\"': return lept_parse_string(c, v);
        case '[': return lept_parse_array(c, v);
        case '{': return lept_parse_object(c, v);
        default:   return lept_parse_number(c, v);
    }
}

void lept_free(lept_value* v) {
    size_t i;
    assert(v != NULL);
    switch(v->type) {
        case LEPT_STRING:
            free(v->u.s.s);
            break;
        case LEPT_ARRAY:
            for (i = 0; i < v->u.a.size; i++) {
                lept_free(&v->u.a.e[i]);
            }
            free(v->u.a.e);
            break;
        case LEPT_OBJECT:
            for (i = 0; i < v->u.o.size; i++) {
                free(v->u.o.m[i].k);
                lept_free(&v->u.o.m[i].v);
            }
            free(v->u.o.m);
            break;
        default:
            break;
    }
    v->type = LEPT_NULL;
}

void lept_set_null(lept_value* v) {
    lept_free(v);
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_number(lept_value* v, double n) {
    assert(v != NULL);
    lept_free(v);
    v->u.n = n;
    v->type = LEPT_NUMBER;
}

size_t lept_get_array_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

size_t lept_get_array_capacity(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.capacity;
}

lept_value* lept_get_array_element(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

size_t lept_get_object_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

const char* lept_get_object_key(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

lept_value* lept_get_object_value(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}

int lept_parse(lept_value* v, const char* json) {
    assert(v != NULL);
    lept_init(v);
    lept_free(v);
    int ret;

    lept_context c;
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

static void lept_stringify_string(lept_context* c, const char* s, size_t len) {
    static const char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    size_t i, size;
    char* head; 
    char* p;
    assert(s != NULL);
    /*
     * e.g.
     * \u0024 --> \x24 ===> * 6
     * double quotes   ===> + 2
     */
    p = head = lept_context_push(c, size = len * 6 + 2);
    *p++ = '"';
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case '\"': *p++ = '\\'; *p++ = '\"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\b': *p++ = '\\'; *p++ = 'b';  break;
            case '\f': *p++ = '\\'; *p++ = 'f';  break;
            case '\n': *p++ = '\\'; *p++ = 'n';  break;
            case '\r': *p++ = '\\'; *p++ = 'r';  break;
            case '\t': *p++ = '\\'; *p++ = 't';  break;
            default:
                if (ch < 0x20) {
                    *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                    *p++ = hex_digits[ch >> 4];
                    *p++ = hex_digits[ch & 15];
                }
                else
                    *p++ = s[i];
        }
    }
    *p++ = '"';
    c->top -= size - (p - head);
}

static void lept_stringify_value(lept_context* c, const lept_value* v) {
    size_t i;
    switch(v->type) {
        case LEPT_NULL:
            PUTS(c, "null", 4);
            break;
        case LEPT_FALSE:
            PUTS(c, "false", 5);
            break;
        case LEPT_TRUE:
            PUTS(c, "true", 4);
            break;
        case LEPT_NUMBER:
            c->top -= 32 - sprintf(lept_context_push(c, 32), "%.17g", v->u.n); break;
            break;
        case LEPT_STRING:
            lept_stringify_string(c, v->u.s.s, v->u.s.len); break;
            break;
        case LEPT_ARRAY:
            PUTC(c, '[');
            for (i = 0; i < v->u.a.size; i++) {
                if (i > 0) {
                    PUTC(c, ',');
                }
                lept_stringify_value(c, &v->u.a.e[i]);
            }
            PUTC(c, ']');
            break;
        case LEPT_OBJECT:
            PUTC(c, '{');
            for (i = 0; i < v->u.o.size; i++) {
                if (i > 0) {
                    PUTC(c, ',');
                }
                lept_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
                PUTC(c, ':');
                lept_stringify_value(c, &v->u.o.m[i].v);
            }
            PUTC(c, '}');
            break;
        default:
            assert(0 && "invalid type");
    }
}

char* lept_stringify(const lept_value* v, size_t* length) {
    lept_context c;
    assert(v != NULL);
    c.stack = (char*) malloc(c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c, v);
    if (length != NULL) {
        *length = c.top;
    }
    PUTC(&c, '\0'); // put NUL terminal
    return c.stack;
}

size_t lept_find_object_index(const lept_value* v, const char* key, size_t klen) {
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL); 
    size_t i;
    for (i = 0; i < v->u.o.size; i++)
        if (v->u.o.m[i].klen == klen && memcmp(v->u.o.m[i].k, key, klen) == 0)
            return i;
    return LEPT_KEY_NOT_EXIST;
}

lept_value* lept_find_object_value(const lept_value* v, const char* key, size_t klen) {
    size_t index = lept_find_object_index(v, key, klen);
    return index != LEPT_KEY_NOT_EXIST ? &v->u.o.m[index].v : NULL;
}

void lept_set_object(lept_value* v, size_t capacity) {
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_OBJECT;
    v->u.o.size = 0;
    v->u.o.capacity = capacity;
    v->u.o.m = capacity > 0 ? (lept_member*) malloc(capacity * sizeof(lept_member)) : NULL;
}

size_t lept_get_object_capacity(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.capacity;
}

void lept_expand_object(lept_value* v, size_t capacity) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->u.o.capacity < capacity) {
        v->u.o.capacity = capacity;
        v->u.o.m = (lept_member*) realloc(v->u.o.m, capacity * sizeof(lept_member));
    }
}

void lept_shrink_object(lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->u.o.capacity > v->u.o.size) {
        v->u.o.capacity = v->u.o.size;
        v->u.o.m = (lept_member*) realloc(v->u.o.m, v->u.o.capacity * sizeof(lept_member));
    }
}

void lept_clear_object(lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    size_t i;
    for (i = 0; i < v->u.o.size; i++) {
        lept_free(&v->u.o.m[i].v);
        free(v->u.o.m[i].k);
        free(&v->u.o.m[i]);
    }
    v->u.o.size = 0;
}

lept_value* lept_set_object_value(lept_value* v, const char* key, size_t klen) {
    lept_value* value = lept_find_object_value(v, key, klen);
    if (value != NULL) {
        return value;
    }

    if (v->u.o.size == v->u.o.capacity) {
        lept_expand_object(v, v->u.o.capacity == 0 ? 1 : v->u.o.capacity * 2);
    }
    
    lept_init(&v->u.o.m[v->u.o.size].v);
    v->u.o.m[v->u.o.size].k = (char*) malloc(klen + 1);
    memcpy(v->u.o.m[v->u.o.size].k, key, klen);
    v->u.o.m[v->u.o.size].k[klen] = '\0';
    v->u.o.m[v->u.o.size].klen = klen;
    return &v->u.o.m[v->u.o.size++].v;
}

int lept_is_equal(const lept_value* lhs, const lept_value* rhs) {
    assert(lhs != NULL && rhs != NULL);
    size_t i;
    if (lhs->type != rhs->type)
        return 0;
    switch (lhs->type) {
        case LEPT_STRING:
            return lhs->u.s.len == rhs->u.s.len && 
                memcmp(lhs->u.s.s, rhs->u.s.s, lhs->u.s.len) == 0;
        case LEPT_NUMBER:
            return lhs->u.n == rhs->u.n;
        case LEPT_ARRAY:
            if (lhs->u.a.size != rhs->u.a.size) {
                return 0;
            }
            for (i = 0; i < lhs->u.a.size; i++) {
                if (!lept_is_equal(&lhs->u.a.e[i], &rhs->u.a.e[i])) {
                    return 0;
                }
            }
            return 1;
        case LEPT_OBJECT:
            if (lhs->u.o.size != rhs->u.o.size) {
                return 0;
            }
            for (i = 0; i < lhs->u.o.size; i++) {
                lept_value* rhs_value = lept_find_object_value(rhs, lhs->u.o.m[i].k, lhs->u.o.m[i].klen);
                if (rhs_value == NULL) {
                    return 0;
                }
                if (!lept_is_equal(&lhs->u.o.m[i].v, rhs_value)) {
                    return 0;
                }
            }
            return 1;
        default:
            return 1;
    }
}

void lept_copy(lept_value* dst, const lept_value* src) {
    size_t i;
    assert(src != NULL && dst != NULL && src != dst);
    switch (src->type) {
        case LEPT_STRING:
            lept_set_string(dst, src->u.s.s, src->u.s.len);
            break;
        case LEPT_ARRAY:
            lept_set_array(dst, src->u.a.capacity);
            dst->u.a.size = src->u.a.size;
            for (i = 0; i < src->u.a.size; i++) {
                lept_init(&dst->u.a.e[i]);
                lept_copy(&dst->u.a.e[i], &src->u.a.e[i]);
            }
            break;
        case LEPT_OBJECT:
            lept_set_object(dst, src->u.o.capacity);
            dst->u.o.size = src->u.o.size;
            for (i = 0; i < src->u.o.size; i++) {
                dst->u.o.m[i].klen = src->u.o.m[i].klen;
                dst->u.o.m[i].k = malloc(src->u.o.m[i].klen * sizeof(char));
                memcpy(dst->u.o.m[i].k, src->u.o.m[i].k, dst->u.o.m[i].klen);
                lept_init(&dst->u.o.m[i].v);
                lept_copy(&dst->u.o.m[i].v, &src->u.o.m[i].v);
            }
            break;
        default:
            lept_free(dst);
            memcpy(dst, src, sizeof(lept_value));
            break;
    }
}

void lept_move(lept_value* dst, lept_value* src) {
    assert(dst != NULL && src != NULL && src != dst);
    lept_free(dst);
    memcpy(dst, src, sizeof(lept_value));
    lept_init(src);
}

void lept_swap(lept_value* lhs, lept_value* rhs) {
    assert(lhs != NULL && rhs != NULL);
    if (lhs != rhs) {
        lept_value temp;
        memcpy(&temp, lhs, sizeof(lept_value));
        memcpy(lhs, rhs, sizeof(lept_value));
        memcpy(rhs, &temp, sizeof(lept_value));
    }
}

void lept_expand_array(lept_value* v, size_t capacity) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.capacity < capacity) {
        v->u.a.capacity = capacity;
        v->u.a.e = (lept_value*) realloc(v->u.a.e, capacity * sizeof(lept_value));
    }
}

void lept_shrink_array(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.capacity > v->u.a.size) {
        v->u.a.capacity = v->u.a.size;
        v->u.a.e = (lept_value*) realloc(v->u.a.e, v->u.a.capacity * sizeof(lept_value));
    }
}

lept_value* lept_pushback_array_element(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.size == v->u.a.capacity)
        lept_expand_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
    lept_init(&v->u.a.e[v->u.a.size]);
    return &v->u.a.e[v->u.a.size++];
}

void lept_popback_array_element(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY && v->u.a.size > 0);
    v->u.a.size--;
    lept_free(&v->u.a.e[v->u.a.size]);
}

lept_value* lept_insert_array_element(lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY && index <= v->u.a.size);
    lept_pushback_array_element(v);

    size_t i;
    for (i = v->u.a.size - 1; i > index; i--) {
        lept_copy(&v->u.a.e[i], &v->u.a.e[i-1]);
    }
    lept_init(&v->u.a.e[index]);

    return &v->u.a.e[index];
}

void lept_erase_array_element(lept_value* v, size_t index, size_t count) {
    assert(v != NULL && v->type ==LEPT_ARRAY && index < v->u.a.size);
    size_t i;
    for (i = index; i + count < v->u.a.size; i++) {
        lept_copy(&v->u.a.e[i], &v->u.a.e[i+count]);
    }
    size_t len = v->u.a.size;
    for (; i < len; i++) {
        lept_popback_array_element(v);
    }
}

void lept_clear_array(lept_value* v) {
    assert(v != NULL && v->type ==LEPT_ARRAY);
    size_t i;
    for (i = 0; i < v->u.a.size; i++) {
        lept_free(&v->u.a.e[i]);
    }
    v->u.a.size = 0;
}
