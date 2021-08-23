#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL, strtod() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <string.h>  /* memcpy() */

#define EXPECT(c, ch) do { assert(*c->json == (ch)); c->json++; } while(0)

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

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

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

#define PUTC(c, ch) do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

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

static int lept_parse_array(lept_context* c, lept_value* v) {
    size_t size = 0;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);

    // empty array
    if (*(c->json) == ']') {
        c->json++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
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
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size *= sizeof(lept_value);
            memcpy(v->u.a.e = (lept_value*)malloc(size), lept_context_pop(c, size), size);
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
        lept_init(&(m.v));

        // parse key to m.k, m.klen
        if (*(c -> json) != '"') {
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

        // parse value
        if ((ret = lept_parse_value(c, &(m.v))) != LEPT_PARSE_OK) {
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
            size_t total_size = sizeof(lept_member) * size;
            c->json++;
            v->type = LEPT_OBJECT;
            v->u.o.size = total_size;
            memcpy(v->u.o.m = (lept_member*)malloc(total_size), lept_context_pop(c, total_size), total_size);
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

lept_value* lept_get_array_element(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return &(v->u.a.e[index]);
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
    return &(v->u.o.m[index].v);
}

int lept_parse(lept_value* v, const char* json) {
    assert(v != NULL);
    lept_init(v);

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
