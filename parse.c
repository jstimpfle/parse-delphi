#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#define UNUSED
#define NORETURN __declspec(noreturn)
#define UNREACHABLE() assert(0);
#else
#define UNUSED __attribute__((unused))
#define NORETURN __attribute__((noreturn))
#define UNREACHABLE() __builtin_unreachable()
#endif
#define NOTIMPLEMENTED() fatal("In %s:%d: %s(): not implemented!", \
                               __FILE__, __LINE__, __func__)
#define CLEAR(x) memset(&(x), 0, sizeof (x))
#define LENGTH(a) ((int) (sizeof (a) / sizeof (a)[0]))
#define SORT(a, n, cmp) qsort(a, n, sizeof *(a), cmp)

void NORETURN fatal(const char *msg, ...)
{
        va_list ap;
        va_start(ap, msg);
        fprintf(stderr, "FATAL: ");
        vfprintf(stderr, msg, ap);
        fprintf(stderr, "\n");
        va_end(ap);
        abort();
}

/***************************************************************************
 * MEMORY ALLOCATION
 **************************************************************************/

struct Alloc {
        int cap;
};

void _buf_init(void **ptr, struct Alloc *alloc, int elsize,
               const char *UNUSED file, int UNUSED line)
{
        *ptr = NULL;
        CLEAR(*alloc);
}

void _buf_exit(void **ptr, struct Alloc *alloc, int elsize,
               const char *UNUSED file, int UNUSED line)
{
        free(*ptr);
        *ptr = NULL;
        CLEAR(*alloc);
}

void _buf_reserve(void **ptr, struct Alloc *alloc, int nelems, int elsize,
                  int clear, const char *UNUSED file, int UNUSED line)
{
        int cnt;
        void *p;
        if (alloc->cap < nelems) {
                cnt = nelems;
                cnt = 2*cnt - 1; while (cnt & (cnt-1)) cnt = cnt & (cnt-1);
                p = realloc(*ptr, cnt * elsize);
                if (!p)
                        fatal("OOM!");
                if (clear)
                        memset((char*)p + alloc->cap * elsize, 0,
                               (cnt - alloc->cap) * elsize);
                *ptr = p;
                alloc->cap = cnt;
        }
}

#define BUF_INIT(buf, cap) \
        _buf_init((void**)&(buf), &(cap), sizeof(*(buf)), __FILE__, __LINE__);
#define BUF_EXIT(buf, cap) \
        _buf_exit((void**)&(buf), &(cap), sizeof(*(buf)), __FILE__, __LINE__);
#define BUF_RESERVE(buf, cap, cnt) \
        _buf_reserve((void**)&(buf), &(cap), (cnt), sizeof(*(buf)), 0, \
                     __FILE__, __LINE__);
#define BUF_RESERVE_Z(buf, cap, cnt) \
        _buf_reserve((void**)&(buf), &(cap), (cnt), sizeof(*(buf)), 1, \
                     __FILE__, __LINE__);
#define BUF_APPEND(buf, cap, cnt, el) \
        do { \
        int _appendpos = (cnt)++; \
        BUF_RESERVE((buf), (cap), _appendpos+1); (buf)[_appendpos] = el; \
        } while (0)

/***************************************************************************
 * STRING INTERNING
 **************************************************************************/

typedef int String;  // points into *string

struct StrEntry {
        String str;
        int next;  // points into *strmap
};

int strbufCnt;
int stringCnt;
int strmapCnt;  // hashmap size. Must be power-of-2 for hash algorithm to work
int strentCnt;

char *strbuf;  // string data backing buffer
int *stroff;   // Offsets. Size: stringCnt+1 to support get_strlen()
int *strmap;   // table of pointers into *strent
struct StrEntry *strent;  // hashmap entry type

struct Alloc strbufAlloc;
struct Alloc stroffAlloc;
struct Alloc strentAlloc;
struct Alloc strmapAlloc;

const char *get_cstr(String s)
{
        return strbuf + stroff[s];
}

int get_strlen(String s)
{
        return stroff[s+1] - stroff[s] - 1;
}

unsigned _computehash(const void *str, int len)
{
        int i;
        unsigned hsh = 5381;
        for (i = 0; i < len; i++)
                hsh = 33*hsh + ((const unsigned char *)str)[i];
        return hsh;
}

int _hashlookup(const void *str, int len, unsigned hsh)
{
        int i;
        int ent;
        unsigned pos = hsh & (strmapCnt - 1);
        for (ent = strmap[pos]; ent != -1; ent = strent[ent].next) {
                i = strent[ent].str;
                if (get_strlen(i) == len && memcmp(get_cstr(i), str, len) == 0)
                        return i;
        }
        return -1;
}

void _hashinsert(unsigned hsh, String idx)
{
        unsigned pos = hsh & (strmapCnt - 1);
        strentCnt ++;
        BUF_RESERVE(strent, strentAlloc, strentCnt);
        strent[strentCnt-1].str = idx;
        strent[strentCnt-1].next = strmap[pos];
        strmap[pos] = strentCnt-1;
}

void _rehash(void)
{
        int i;

        BUF_RESERVE(strmap, strmapAlloc, strmapCnt);
        for (i = 0; i < strmapCnt; i++)
                strmap[i] = -1;
        strentCnt = 0;
        for (i = 0; i < stringCnt; i++) {
                const void *str = get_cstr(i);
                int len = get_strlen(i);
                _hashinsert(_computehash(str, len), i);
        }
}

String intern_string(const void *str, int len)
{
        unsigned hsh;
        int i;

        if (2 * strmapCnt <= 3 * strentCnt) {
                if (strmapCnt == 0)
                        strmapCnt = 256;
                while (2 * strmapCnt < 3 * strentCnt)
                        strmapCnt *= 2;
                _rehash();
        }
        assert((strmapCnt & (strmapCnt-1)) == 0);  // MUST BE POWER OF 2 !!!!

        hsh = _computehash(str, len);
        i = _hashlookup(str, len, hsh);
        if (i != -1)
                return i;

        BUF_RESERVE(stroff, stroffAlloc, stringCnt + 2);
        stroff[stringCnt] = strbufCnt;
        stroff[stringCnt+1] = strbufCnt + len + 1;
        stringCnt ++;

        BUF_RESERVE(strbuf, strbufAlloc, strbufCnt + len + 1);
        memcpy(strbuf + strbufCnt, str, len);
        strbuf[strbufCnt + len] = '\0';
        strbufCnt += len + 1;

        _hashinsert(hsh, stringCnt-1);
        return stringCnt - 1;
}

String intern_cstring(const char *str)
{
        return intern_string(str, strlen(str));
}

/***************************************************************************
 * FILES CONTENTS
 **************************************************************************/

typedef int File;  // File system file. Points into fileInfo and fileContents.

struct FileInfo {
        String filepath;
};

/* We read files all at once and keep the contents in-memory. A win for
 * simplicity and probably not a big loss in terms of memory efficiency, since
 * it avoids making many small memory allocations */

struct FileContents {
        unsigned char *buf;  // for now, every file is separate.
        struct Alloc alloc;
        int size;
};

int fileCnt;
struct FileInfo *fileInfo;
struct FileContents *fileContents;
struct Alloc fileInfoAlloc;
struct Alloc fileContentsAlloc;

void read_file_contents(File file)
{
        FILE *f;
        size_t nread;
        const int chunksize = 4096;
        const char *fpath;

        fpath = get_cstr(fileInfo[file].filepath);
        f = fopen(fpath, "rb");
        if (f == NULL)
                fatal("Failed to open file %s", fpath);

        while (!feof(f) && !ferror(f)) {
                BUF_RESERVE(fileContents[file].buf, fileContents[file].alloc,
                            fileContents[file].size + chunksize);
                nread = fread(fileContents[file].buf + fileContents[file].size,
                              1, chunksize, f);
                fileContents[file].size += (int) nread;
        }
        BUF_RESERVE_Z(fileContents[file].buf, fileContents[file].alloc,
                      fileContents[file].size + 1); // terminating 0
        if (ferror(f))
                fatal("I/O error while reading from %s", fpath);
        fclose(f);
}

/***************************************************************************
 * FILE STREAM ABSTRACTION
 **************************************************************************/
/* The fact that we read the whole file at once is abstracted here. We should
 * not depend on it. */

#define STREAM_END -1

int *bytePos;  /* count == fileCnt */
int *lineNo;  /* count == fileCnt. Starting at 1. */

struct Alloc bytePosAlloc;
struct Alloc lineNoAlloc;

int havebyte(File file)
{
        return bytePos[file] < fileContents[file].size;
}

int currentbyte(File file)
{
        if (!havebyte(file))
                return STREAM_END;
        return ((char *) fileContents[file].buf)[bytePos[file]];
}

int nextbyte(File file)
{
        if (currentbyte(file) == '\n')
                lineNo[file] ++;
        bytePos[file] ++;
        return currentbyte(file);
}

/***************************************************************************
 * PROGRAM REPRESENTATION
 **************************************************************************/

typedef int Token;
typedef int Program;  // Program (in a .dpr file).
typedef int Unit;    // Unit (implementation file). Points into unitInfo
typedef int Scope;   // Any scope. Points into scopeInfo
typedef int Access;  // ACCESS_?
typedef int Record;
typedef int RecordMember;
typedef int Type;
typedef int Const;
typedef int Var;
typedef int Prochead;  // procedure signature (forward decl or including body)
typedef int Procbody;
typedef int Proctype;
typedef int Symbol;
typedef int Symref;

/* Token kinds */
enum {
        TOK_NAME,
        TOK_NUMBER,
        TOK_STRING,
        TOK_PARENLEFT,
        TOK_PARENRIGHT,
        TOK_BRACKETLEFT,
        TOK_BRACKETRIGHT,
        TOK_KWPROGRAM,
        TOK_KWUSES,
        TOK_KWIN,
        TOK_KWUNIT,
        TOK_KWINTERFACE,
        TOK_KWIMPLEMENTATION,
        TOK_KWINITIALIZATION,
        TOK_KWTYPE,
        TOK_KWVAR,
        TOK_KWCONST,
        TOK_KWFUNCTION,
        TOK_KWPROCEDURE,
        TOK_KWOVERLOAD,
        TOK_KWINLINE,
        TOK_KWVIRTUAL,
        TOK_KWABSTRACT,
        TOK_KWOVERRIDE,
        TOK_KWFORWARD,
        TOK_KWLABEL,
        TOK_KWRECORD,
        TOK_KWCLASS,
        TOK_KWPUBLIC,
        TOK_KWPRIVATE,
        TOK_KWPROTECTED,
        TOK_KWARRAY,
        TOK_KWOF,
        TOK_KWIF,
        TOK_KWTHEN,
        TOK_KWELSE,
        TOK_KWFOR,
        TOK_KWWHILE,
        TOK_KWREPEAT,
        TOK_KWUNTIL,
        TOK_KWTO,
        TOK_KWDOWNTO,
        TOK_KWCASE,
        TOK_KWTRY,
        TOK_KWEXCEPT,
        TOK_KWDO,
        TOK_KWBEGIN,
        TOK_KWEND,
        TOK_KWDIV,
        TOK_KWNOT,
        TOK_KWAND,
        TOK_KWOR,
        TOK_KWXOR,
        TOK_KWSHL,
        TOK_KWSHR,
        TOK_PLUS,
        TOK_MINUS,
        TOK_STAR,
        TOK_SLASH,
        TOK_ATSIGN,
        TOK_CARET,
        TOK_COLON,
        TOK_ASSIGN,
        TOK_LT,
        TOK_LE,
        TOK_EQ,
        TOK_NE,
        TOK_GE,
        TOK_GT,
        TOK_SEMICOLON,
        TOK_COMMA,
        TOK_DOT,
        TOK_WHITESPACE,
        TOK_COMMENTBRACE,
        TOK_COMMENTPAREN,
        TOK_COMMENTCXX,
        TOK_DIRECTIVE,
        NUM_TOKS,
};

/* Directive kinds (Preprocessor!) */
enum {
        DIRECTIVE_ALIGN,
        DIRECTIVE_APPTYPE,
        DIRECTIVE_ASSERTIONS,
        DIRECTIVE_BOOLEVAL,
        DIRECTIVE_CODEALIGN,
        DIRECTIVE_DEBUGINFO,
        DIRECTIVE_DEFINE,
        DIRECTIVE_DENYPACKAGEUNIT,
        DIRECTIVE_DESCRIPTION,
        DIRECTIVE_DESIGNONLY,
        DIRECTIVE_ELSE,
        DIRECTIVE_ELSEIF,
        DIRECTIVE_ENDIF,
        DIRECTIVE_EXTENSION,
        DIRECTIVE_OBJEXPORTALL,
        DIRECTIVE_EXTENDEDSYNTAX,
        DIRECTIVE_EXTENDEDCOMPATIBILITY,
        DIRECTIVE_EXCESSPRECISION,
        DIRECTIVE_HIGHCHARUNICODE,
        DIRECTIVE_HINTS,
        DIRECTIVE_IFDEF,
        DIRECTIVE_IF,
        DIRECTIVE_IFEND,
        DIRECTIVE_IFNDEF,
        DIRECTIVE_IFOPT,
        DIRECTIVE_IMAGEBASE,
        DIRECTIVE_IMPLICITBUILD,
        DIRECTIVE_IMPORTEDDATA,
        DIRECTIVE_INCLUDE,
        DIRECTIVE_IOCHECKS,
        DIRECTIVE_LIBPREFIX,
        DIRECTIVE_LIBSUFFIX,
        DIRECTIVE_LIBVERSION,
        DIRECTIVE_LEGACYIFEND,
        DIRECTIVE_LINK,
        DIRECTIVE_LOCALSYMBOLS,
        DIRECTIVE_LONGSTRINGS,
        DIRECTIVE_MINSTACKSIZE,
        DIRECTIVE_MAXSTACKSIZE,
        DIRECTIVE_MESSAGE,
        DIRECTIVE_METHODINFO,
        DIRECTIVE_MINENUMSIZE,
        DIRECTIVE_OLDTYPELAYOUT,
        DIRECTIVE_OPENSTRINGS,
        DIRECTIVE_OPTIMIZATION,
        DIRECTIVE_OVERFLOWCHECKS,
        DIRECTIVE_SETPEFLAGS,
        DIRECTIVE_SETPEOPTFLAGS,
        DIRECTIVE_SETPEOSVERSION,
        DIRECTIVE_SETPESUBSYSVERSION,
        DIRECTIVE_SETPEUSERVERSION,
        DIRECTIVE_SAFEDIVIDE,
        DIRECTIVE_POINTERMATH,
        DIRECTIVE_RANGECHECKS,
        DIRECTIVE_REALCOMPATIBILITY,
        DIRECTIVE_REGION,
        DIRECTIVE_ENDREGION,
        DIRECTIVE_RESOURCE,
        DIRECTIVE_RESOURCERESERVE,
        DIRECTIVE_RTTI,
        DIRECTIVE_RUNONLY,
        DIRECTIVE_TYPEINFO,
        DIRECTIVE_SCOPEDENUMS,
        DIRECTIVE_STACKFRAMES,
        DIRECTIVE_STRONGLINKTYPES,
        DIRECTIVE_REFERENCEINFO,
        DIRECTIVE_DEFINITIONINFO,
        DIRECTIVE_TYPEADDRESS,
        DIRECTIVE_UNDEF,
        DIRECTIVE_VARSTRINGCHECKS,
        DIRECTIVE_WARN,
        DIRECTIVE_WARNINGS,
        DIRECTIVE_WEAKPACKAGEUNIT,
        DIRECTIVE_WEAKLINKRTTI,
        DIRECTIVE_WRITEABLECONST,
        DIRECTIVE_ZEROBASEDSTRINGS,
        NUM_DIRECTIVES,
};

/* Scope kinds (symbol resolution!) */
enum {
        SCOPE_PROGRAM,
        SCOPE_INTERFACE,
        SCOPE_IMPLEMENTATION,
        SCOPE_RECORD,
        SCOPE_PROCHEAD,
        SCOPE_PROCBODY,
        NUM_SCOPE_KINDS,
};

/* Symbol kinds. A symbol is a name / identifier that is defined somewhere and
 * referenced (used) in other places. */
enum {
        SYMBOL_UNIT,
        SYMBOL_TYPE,
        SYMBOL_CONST,
        SYMBOL_VAR,
        SYMBOL_PROC,
        NUM_SYMBOL_KINDS,
};

/*
 * A Symref (symbol reference) is either resolved by scoping rules, or it is
 * relative to a known structure (e.g. record members relative to a record). In
 * the latter case the structure is identified by another Symref.
 *
 * Strictly RELATIVE Symrefs aren't really "symbol" references I guess - but in
 * the language's syntax both can occur in the same places.
 */
enum {
        SYMREF_SCOPE,
        SYMREF_RELATIVE,
};

enum {
        TYPE_BUILTIN,  // integer, string etc
        TYPE_RECORD,   // record type with members
        TYPE_PROC,  // procedure or function
};

enum {
        ACCESS_PUBLIC,
        ACCESS_PRIVATE,
        ACCESS_PROTECTED,
};

enum {
        UNITNOTFOUND = -1,  // "Unit-not-found" unit.
        SYMBOLNOTFOUND = -1,  // "Symbol-not-found" symbol.
};

struct TokenInfo {
        int kind;  // TOK_??
        int offset;  // offset in bytes from start of file
        int lineno;  // line number in file
        union {
                struct {
                        String tName;
                        String tOrigname;
                };
                double tNumber;
                String tString;
                String tWhitespace;
                String tComment;
                String tDirective;
        };
};

struct ProgramInfo {
        String fqname;
        String name;
        String project_default_namespace;  // computed from namespace
};

struct UnitInfo {
        String fqname;  // fully qualified name (MyCompany.MyProgram.MyUnit)
        String name;    // name (MyUnit)
        /*
         * namespace (MyCompany.MyProgram)
         *
         * If there is only a single component in the sourcefile (e.g.  "Unit
         * MyUnit;") then this is called a *generic unit*, and this fields gets
         * assigned the *project default namespace* from ProgramInfo above.
         *
         * (I THINK GENERIC UNITS ARE A BAD IDEA: Do we need to re-parse this
         * unit for every program then?)
         */
        String namespace;
        File file;
        /* lookup indices. Only set later */
        Scope ifaceScope;
        Scope implScope;
        int ifaceUsesFirst;
        int ifaceUsesLast;
        int implUsesFirst;
        int implUsesLast;
};

struct ProgramUses {
        /* The uses clause in "programs or libraries" (and I assume packages as
         * well) has a slightly different meaning than in Units. Also, the
         * "in" keyword (with which a unit filepath is specified) is allowed
         * there. */
        Program program;
        String depname;
        String pathspec;  // may be empty (i.e. '')
};

struct UnitUses {
        Unit unit;
        String depname;
        Unit dep;  // set only later
};

struct ScopeInfo {
        int kind;  // SCOPE_??
        union {
                Program tProgram;
                Unit tUnit;
                Prochead tProchead;
                Procbody tProcbody;
        };
        Symbol firstSymbol;
        Symbol lastSymbol;
};

struct SymbolInfo {  /* symbol definition */
        String name;
        Scope scope;
        int kind;  // SYMBOL_??
        union {
                Type tType;  // if SYMBOL_TYPE
                Const tConst;  // if SYMBOL_CONST
                Var tVar;  // if SYMBOL_VAR
                Prochead tProc;  // XXX: really "Head", not rather just "Proc"?
        };
        // Meta information. Must be a TOK_NAME token with tName == name.
        Token token;
};

struct SymrefInfo {  /* symbol reference */
        int kind;  // SYMREF_??
        union {
                // if SYMREF_SCOPE
                struct {
                        // symbol name
                        String name;
                        // the scope from where the reference was made
                        Scope scope;
                        // resolved later. Points into symbol array
                        Symbol symbol;
                } tScope;
                // if SYMREF_RELATIVE
                struct {
                        String name;  // "member" name
                        Symref relativeTo;
                } tRelative;
        };
        // Meta information. Must be a TOK_NAME token with tName == name.
        Token token;
        // Resolved later
        Type type;
};

struct RecordInfo {
        RecordMember firstMember;
        RecordMember lastMember;
};

struct RecordMember {
        Record record;
        String name;
        Type type;
        Access access;
};

struct TypeInfo {
        int kind;  // TYPE_??
        union {
                Record tRecord;  // if TYPE_RECORD
                Proctype tProctype;  // if TYPE_PROC
        };
};

struct ProctypeInfo {
        Scope procheadscope;
        Type returntype;  // -1 if procedure. Set only later!
};

struct ConstInfo {
        String name;
        Type type;
        Scope scope;
};

struct VarInfo {
        String name;
        Type type;
        Scope scope;
};

struct ProcheadInfo {
        String namespace;  // first dot-part if method, empty if global
        String name;
        Type type;  // must be TYPE_PROC type
        Scope scope;  // scope for proc arguments
        // parent scope: SCOPE_INTERFACE or SCOPE_IMPLEMENTATION or SCOPE_RECORD
        Scope parent;
        // -1 if global function/procedure. Otherwise, record (/class)
        // only valid after symbol resolution and type checking
        Record record;
};

struct ProcbodyInfo {
        Prochead head;
        Scope scope;
};

int tokenCnt;
int unitCnt;
int programCnt;
int programUsesCnt;
int ifaceUsesCnt;
int implUsesCnt;
int usesDepCnt;
int scopeCnt;
int recordCnt;
int recordMemberCnt;
int typeCnt;
int constCnt;
int varCnt;
int procHeadCnt;
int procBodyCnt;
int proctypeCnt;
int symbolCnt;
int symrefCnt;

/* Currently we support only a single project file. It should not be too much
 * work to adapt the program later to support parsing multiple projects at
 * once (assuming that it is ok to parse each source file only once) */
String dprFilepath;

/* ok so we decide to put all tokens parsed from all files into a single
 * contiguous array. If we later want to dynamically update files we might have
 * to look for a different solution */
int *firstToken;
int *lastToken;
int *currentToken;
struct TokenInfo *token;
struct ProgramInfo *programInfo;
struct UnitInfo *unitInfo;
struct ProgramUses *programUses;
struct UnitUses *ifaceUses;
struct UnitUses *implUses;
struct ScopeInfo *scopeInfo;
struct SymbolInfo *symbolInfo;
struct SymrefInfo *symrefInfo;
struct RecordInfo *recordInfo;
struct RecordMember *recordMember;
struct TypeInfo *typeInfo;
struct ConstInfo *constInfo;
struct VarInfo *varInfo;
struct ProcheadInfo *procheadInfo;
struct ProcbodyInfo *procbodyInfo;
struct ProctypeInfo *proctypeInfo;
// speed-up data structures
Unit *unitByName;  // units, sorted by (interned) name

struct Alloc currentTokenAlloc;
struct Alloc firstTokenAlloc;
struct Alloc lastTokenAlloc;
struct Alloc tokenAlloc;
struct Alloc programInfoAlloc;
struct Alloc unitInfoAlloc;
struct Alloc programUsesAlloc;
struct Alloc ifaceUsesAlloc;
struct Alloc implUsesAlloc;
struct Alloc scopeInfoAlloc;
struct Alloc symbolInfoAlloc;
struct Alloc symrefInfoAlloc;
struct Alloc recordInfoAlloc;
struct Alloc recordMemberAlloc;
struct Alloc typeInfoAlloc;
struct Alloc constInfoAlloc;
struct Alloc varInfoAlloc;
struct Alloc procHeadAlloc;
struct Alloc procBodyAlloc;
struct Alloc proctypeAlloc;
struct Alloc unitByNameAlloc;

const char *const scopeKindString[NUM_SCOPE_KINDS] = {
        "SCOPE_PROGRAM",
        "SCOPE_INTERFACE",
        "SCOPE_IMPLEMENTATION",
        "SCOPE_RECORD",
        "SCOPE_PROCHEAD",
        "SCOPE_PROCBODY",
};

const char *const symbolKindString[NUM_SYMBOL_KINDS] = {
        "SYMBOL_UNIT",
        "SYMBOL_TYPE",
        "SYMBOL_CONST",
        "SYMBOL_VAR",
};

File add_file(String filepath)
{
        fileCnt ++;
        BUF_RESERVE(fileInfo, fileInfoAlloc, fileCnt);
        BUF_RESERVE_Z(fileContents, fileContentsAlloc, fileCnt);
        BUF_RESERVE(bytePos, bytePosAlloc, fileCnt);
        BUF_RESERVE(lineNo, lineNoAlloc, fileCnt);
        BUF_RESERVE(currentToken, currentTokenAlloc, fileCnt);
        BUF_RESERVE(firstToken, firstTokenAlloc, fileCnt);
        BUF_RESERVE(lastToken, lastTokenAlloc, fileCnt);
        fileInfo[fileCnt-1].filepath = filepath;
        return fileCnt - 1;
}

void add_type_symbol(String name, Scope scope, Type type, Token tok)
{
        Symbol symbol = symbolCnt ++;
        BUF_RESERVE(symbolInfo, symbolInfoAlloc, symbolCnt);
        symbolInfo[symbol].name = name;
        symbolInfo[symbol].scope = scope;
        symbolInfo[symbol].kind = SYMBOL_TYPE;
        symbolInfo[symbol].tType = type;
        symbolInfo[symbol].token = tok;
}

void add_const_symbol(String name, Scope scope, Const theconst, Token tok)
{
        Symbol symbol = symbolCnt ++;
        BUF_RESERVE(symbolInfo, symbolInfoAlloc, symbolCnt);
        symbolInfo[symbol].name = name;
        symbolInfo[symbol].scope = scope;
        symbolInfo[symbol].kind = SYMBOL_CONST;
        symbolInfo[symbol].tConst = theconst;
        symbolInfo[symbol].token = tok;
}

void add_var_symbol(String name, Scope scope, Var thevar, Token tok)
{
        Symbol symbol = symbolCnt ++;
        BUF_RESERVE(symbolInfo, symbolInfoAlloc, symbolCnt);
        symbolInfo[symbol].name = name;
        symbolInfo[symbol].scope = scope;
        symbolInfo[symbol].kind = SYMBOL_VAR;
        symbolInfo[symbol].tVar = thevar;
        symbolInfo[symbol].token = tok;
}

void add_proc_symbol(String name, Scope scope, Prochead head, Token tok)
{
        printf("add proc symbol %s\n", get_cstr(token[tok].tOrigname));
        Symbol symbol = symbolCnt ++;
        BUF_RESERVE(symbolInfo, symbolInfoAlloc, symbolCnt);
        symbolInfo[symbol].name = name;
        symbolInfo[symbol].scope = scope;
        symbolInfo[symbol].kind = SYMBOL_PROC;
        symbolInfo[symbol].tProc = head;
        symbolInfo[symbol].token = tok;
}

Const add_const(String name, Scope scope, Type type, Token tok)
{
        Const theconst = constCnt ++;
        BUF_RESERVE(constInfo, constInfoAlloc, constCnt);
        constInfo[theconst].name = name;
        constInfo[theconst].type = type;
        constInfo[theconst].scope = scope;
        add_const_symbol(name, scope, theconst, tok);
        return theconst;
}

Var add_var(String name, Scope scope, Type type, Token tok)
{
        Var thevar = varCnt ++;
        BUF_RESERVE(varInfo, varInfoAlloc, varCnt);
        varInfo[thevar].name = name;
        varInfo[thevar].type = type;
        varInfo[thevar].scope = scope;
        add_var_symbol(name, scope, thevar, tok);
        return thevar;
}

void add_record_member(Record record, String name, Type type, Access access)
{
        recordMemberCnt ++;
        BUF_RESERVE(recordMember, recordMemberAlloc, recordMemberCnt);
        recordMember[recordMemberCnt-1].record = record;
        recordMember[recordMemberCnt-1].name = name;
        recordMember[recordMemberCnt-1].type = type;
        recordMember[recordMemberCnt-1].access = access;
}

Type add_record_type(Record record)
{
        typeCnt ++;
        BUF_RESERVE(typeInfo, typeInfoAlloc, typeCnt);
        typeInfo[typeCnt-1].kind = TYPE_RECORD;
        typeInfo[typeCnt-1].tRecord = record;
        return typeCnt - 1;
}

Type add_proc_type(Proctype proctype)
{
        Type tp = typeCnt ++;
        BUF_RESERVE(typeInfo, typeInfoAlloc, typeCnt);
        typeInfo[tp].kind = TYPE_PROC;
        typeInfo[tp].tProctype = proctype;
        return tp;
}

Type add_builtin_type(void)
{
        Type tp = typeCnt ++;
        BUF_RESERVE(typeInfo, typeInfoAlloc, typeCnt);
        typeInfo[tp].kind = TYPE_BUILTIN;  // TODO
        return tp;
}

Proctype add_proctypeInfo(Scope procheadscope)
{
        Proctype pt = proctypeCnt ++;
        BUF_RESERVE(proctypeInfo, proctypeAlloc, proctypeCnt);
        proctypeInfo[pt].procheadscope = procheadscope;
        proctypeInfo[pt].returntype = -1;
        return pt;
}

Symref add_scoped_symref(String name, Scope scope, Token tok)
{
        symrefCnt ++;
        BUF_RESERVE(symrefInfo, symrefInfoAlloc, symrefCnt);
        symrefInfo[symrefCnt-1].kind = SYMREF_SCOPE;
        symrefInfo[symrefCnt-1].tScope.name = name;
        symrefInfo[symrefCnt-1].tScope.scope = scope;
        symrefInfo[symrefCnt-1].tScope.symbol = SYMBOLNOTFOUND;  // resolved later
        symrefInfo[symrefCnt-1].token = tok;
        symrefInfo[symrefCnt-1].type = -1;  // resolved later
        return symrefCnt - 1;
}

Symref add_relative_symref(String name, Symref relativeTo, Token tok)
{
        symrefCnt ++;
        BUF_RESERVE(symrefInfo, symrefInfoAlloc, symrefCnt);
        symrefInfo[symrefCnt-1].kind = SYMREF_RELATIVE;
        symrefInfo[symrefCnt-1].tRelative.name = name;
        symrefInfo[symrefCnt-1].tRelative.relativeTo = relativeTo;
        symrefInfo[symrefCnt-1].token = tok;
        symrefInfo[symrefCnt-1].type = -1;  // resolved later
        return symrefCnt - 1;
}

//
void init_builtin_type(String name)
{
        Type type = add_builtin_type();
        printf("ADD BUILTIN TYPE %d\n", type);
        add_type_symbol(name, 0/*SCOPE*/, type, 0/*TOK*/);
}

void init_builtin_types_and_symbols(void)
{
        init_builtin_type(intern_cstring("const"));
        init_builtin_type(intern_cstring("integer"));
        init_builtin_type(intern_cstring("string"));
        init_builtin_type(intern_cstring("boolean"));
}

/***************************************************************************
 * LEXER
 **************************************************************************/

struct TokInfo {
        const char *name;
};

struct KwInfo {
        int kind;  // TOK_??
        const char *kwstring;
};

static struct TokInfo tokInfo[NUM_TOKS] = {
#define MAKE(x) { #x }
        MAKE(TOK_NAME),
        MAKE(TOK_NUMBER),
        MAKE(TOK_STRING),
        MAKE(TOK_PARENLEFT),
        MAKE(TOK_PARENRIGHT),
        MAKE(TOK_BRACKETLEFT),
        MAKE(TOK_BRACKETRIGHT),
        MAKE(TOK_KWPROGRAM),
        MAKE(TOK_KWUSES),
        MAKE(TOK_KWIN),
        MAKE(TOK_KWUNIT),
        MAKE(TOK_KWINTERFACE),
        MAKE(TOK_KWIMPLEMENTATION),
        MAKE(TOK_KWINITIALIZATION),
        MAKE(TOK_KWTYPE),
        MAKE(TOK_KWVAR),
        MAKE(TOK_KWCONST),
        MAKE(TOK_KWFUNCTION),
        MAKE(TOK_KWPROCEDURE),
        MAKE(TOK_KWOVERLOAD),
        MAKE(TOK_KWINLINE),
        MAKE(TOK_KWVIRTUAL),
        MAKE(TOK_KWABSTRACT),
        MAKE(TOK_KWOVERRIDE),
        MAKE(TOK_KWFORWARD),
        MAKE(TOK_KWLABEL),
        MAKE(TOK_KWRECORD),
        MAKE(TOK_KWCLASS),
        MAKE(TOK_KWPUBLIC),
        MAKE(TOK_KWPRIVATE),
        MAKE(TOK_KWPROTECTED),
        MAKE(TOK_KWARRAY),
        MAKE(TOK_KWOF),
        MAKE(TOK_KWIF),
        MAKE(TOK_KWTHEN),
        MAKE(TOK_KWELSE),
        MAKE(TOK_KWFOR),
        MAKE(TOK_KWWHILE),
        MAKE(TOK_KWREPEAT),
        MAKE(TOK_KWUNTIL),
        MAKE(TOK_KWTO),
        MAKE(TOK_KWDOWNTO),
        MAKE(TOK_KWCASE),
        MAKE(TOK_KWTRY),
        MAKE(TOK_KWEXCEPT),
        MAKE(TOK_KWDO),
        MAKE(TOK_KWBEGIN),
        MAKE(TOK_KWEND),
        MAKE(TOK_KWDIV),
        MAKE(TOK_KWNOT),
        MAKE(TOK_KWAND),
        MAKE(TOK_KWOR),
        MAKE(TOK_KWXOR),
        MAKE(TOK_KWSHL),
        MAKE(TOK_KWSHR),
        MAKE(TOK_PLUS),
        MAKE(TOK_MINUS),
        MAKE(TOK_STAR),
        MAKE(TOK_SLASH),
        MAKE(TOK_ATSIGN),
        MAKE(TOK_CARET),
        MAKE(TOK_COLON),
        MAKE(TOK_ASSIGN),
        MAKE(TOK_LT),
        MAKE(TOK_LE),
        MAKE(TOK_EQ),
        MAKE(TOK_NE),
        MAKE(TOK_GE),
        MAKE(TOK_GT),
        MAKE(TOK_SEMICOLON),
        MAKE(TOK_COMMA),
        MAKE(TOK_DOT),
        MAKE(TOK_WHITESPACE),
        MAKE(TOK_COMMENTBRACE),
        MAKE(TOK_COMMENTPAREN),
        MAKE(TOK_COMMENTCXX),
        MAKE(TOK_DIRECTIVE),
#undef MAKE
};

struct KwInfo kwInfo[] = {
#define MAKEKW(t, s) { t, s }
        MAKEKW(TOK_KWPROGRAM, "program"),
        MAKEKW(TOK_KWUSES, "uses"),
        MAKEKW(TOK_KWIN, "in"),
        MAKEKW(TOK_KWUNIT, "unit"),
        MAKEKW(TOK_KWINTERFACE, "interface"),
        MAKEKW(TOK_KWIMPLEMENTATION, "implementation"),
        MAKEKW(TOK_KWINITIALIZATION, "initialization"),
        MAKEKW(TOK_KWTYPE, "type"),
        MAKEKW(TOK_KWVAR, "var"),
        MAKEKW(TOK_KWCONST, "const"),
        MAKEKW(TOK_KWFUNCTION, "function"),
        MAKEKW(TOK_KWPROCEDURE, "procedure"),
        MAKEKW(TOK_KWOVERLOAD, "overload"),
        MAKEKW(TOK_KWINLINE, "inline"),
        MAKEKW(TOK_KWVIRTUAL, "virtual"),
        MAKEKW(TOK_KWABSTRACT, "abstract"),
        MAKEKW(TOK_KWOVERRIDE, "override"),
        MAKEKW(TOK_KWFORWARD, "forward"),
        MAKEKW(TOK_KWLABEL, "label"),
        MAKEKW(TOK_KWRECORD, "record"),
        MAKEKW(TOK_KWCLASS, "class"),
        MAKEKW(TOK_KWPUBLIC, "public"),
        MAKEKW(TOK_KWPRIVATE, "private"),
        MAKEKW(TOK_KWPROTECTED, "protected"),
        MAKEKW(TOK_KWARRAY, "array"),
        MAKEKW(TOK_KWOF, "of"),
        MAKEKW(TOK_KWIF, "if"),
        MAKEKW(TOK_KWTHEN, "then"),
        MAKEKW(TOK_KWELSE, "else"),
        MAKEKW(TOK_KWFOR, "for"),
        MAKEKW(TOK_KWWHILE, "while"),
        MAKEKW(TOK_KWREPEAT, "repeat"),
        MAKEKW(TOK_KWUNTIL, "until"),
        MAKEKW(TOK_KWTO, "to"),
        MAKEKW(TOK_KWDOWNTO, "downto"),
        MAKEKW(TOK_KWCASE, "case"),
        MAKEKW(TOK_KWTRY, "try"),
        MAKEKW(TOK_KWEXCEPT, "except"),
        MAKEKW(TOK_KWDO, "do"),
        MAKEKW(TOK_KWBEGIN, "begin"),
        MAKEKW(TOK_KWEND, "end"),
        MAKEKW(TOK_KWDIV, "div"),
        MAKEKW(TOK_KWNOT, "not"),
        MAKEKW(TOK_KWAND, "and"),
        MAKEKW(TOK_KWOR, "or"),
        MAKEKW(TOK_KWXOR, "xor"),
        MAKEKW(TOK_KWSHL, "shl"),
        MAKEKW(TOK_KWSHR, "shr"),
#undef MAKEKW
};

/* We will intern the keywords at initialization time and give them consecutive
 * string ids. This way we can easily find keywords while lexing. */
String first_keyword;
String last_keyword;

void init_keywords(void)
{
        int i;

        first_keyword = stringCnt;
        for (i = 0; i < LENGTH(kwInfo); i++)
                intern_cstring(kwInfo[i].kwstring);
        last_keyword = stringCnt;
        assert(stringCnt == first_keyword + LENGTH(kwInfo));
}


int isbytealpha(int c)
{
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

int isbytedigit(int c)
{
        return c >= '0' && c <= '9';
}

int isbytewhitespace(int c)
{
        if (c == '\t')
                fatal("Tab character found. TODO: Allow with warnings?");
        return c == ' ' || c == '\r' || c == '\n';
}

void makelower(char *c, int cnt)
{
        int i;
        for (i = 0; i < cnt; i++)
                if (c[i] >= 'A' && c[i] <= 'Z')
                        c[i] += 32;
}

char *lexbuf;
struct Alloc lexbufAlloc;
int lexbufCnt;

int lex_token(File file)
{
        String origstr;
        String str;
        struct TokenInfo t;
        assert(last_keyword - first_keyword == LENGTH(kwInfo)); // initialized?

        if (!havebyte(file))
                return 0;

        CLEAR(t);
        t.offset = bytePos[file];
        t.lineno = lineNo[file];
        if (isbytealpha(currentbyte(file)) || currentbyte(file) == '_') {
                lexbufCnt = 0;
                //BUF_INIT(lexbuf, lexbufAlloc);
                for (;;) {
                        BUF_APPEND(lexbuf, lexbufAlloc, lexbufCnt,
                                   currentbyte(file));
                        nextbyte(file);
                        if (!isbytealpha(currentbyte(file))
                            && !isbytedigit(currentbyte(file))
                            && currentbyte(file) != '_')
                                break;
                }
                origstr = intern_string(lexbuf, lexbufCnt);
                /* delphi is case-insensitive */
                makelower(lexbuf, lexbufCnt);
                str = intern_string(lexbuf, lexbufCnt);

                if (first_keyword <= str && str < last_keyword) {
                        // known keyword
                        t.kind = kwInfo[str - first_keyword].kind;
                }
                else {
                        // new user-define name
                        t.kind = TOK_NAME;
                        t.tName = str;
                        t.tOrigname = origstr;
                }
                //BUF_EXIT(lexbuf, lexbufAlloc);
        }
        else if (isbytedigit(currentbyte(file))) {
                t.kind = TOK_NUMBER;
                int x = currentbyte(file) - '0';
                for (;;) {
                        nextbyte(file);
                        if (!isbytedigit(currentbyte(file)))
                                break;
                        x = 10 * x + currentbyte(file) - '0';
                }
                t.tNumber = x;
        }
        else if (currentbyte(file) == '\'') {
                t.kind = TOK_STRING;
                lexbufCnt = 0;
                //BUF_INIT(lexbuf, lexbufAlloc);
                for (;;) {
                        nextbyte(file);
                        if (!havebyte(file))
                                fatal("While parsing string literal: "
                                      "Unexpected end of stream");
                        if (currentbyte(file) == '\'')
                                break;
                        BUF_APPEND(lexbuf, lexbufAlloc, lexbufCnt,
                                   currentbyte(file));
                }
                t.tString = intern_string(lexbuf, lexbufCnt);
                //BUF_EXIT(lexbuf, lexbufAlloc);
                nextbyte(file);
        }
        else if (currentbyte(file) == '#') {
                t.kind = TOK_STRING;
                nextbyte(file);
                // cleanup: this is a quick copy of the number parsing code
                int x = currentbyte(file) - '0';
                for (;;) {
                        nextbyte(file);
                        if (!isbytedigit(currentbyte(file)))
                                break;
                        x = 10 * x + currentbyte(file) - '0';
                }
                if (!(0 <= x && x < 65536)) {
                        fatal("At %s %d: Hash pound literal found, but value "
                              "is not between 0 and 65535",
                              get_cstr(fileInfo[file].filepath),
                              bytePos[file]);
                }
                if (x >= 256) {
                        printf("WARNING: At %s %d: Hash pound literal with "
                               "value >= 256 found. This is not well "
                               "supported yet!\n",
                               get_cstr(fileInfo[file].filepath),
                               bytePos[file]);
                }
                char c[2] = { x, x >> 8 }; //XXX
                // for now, single-character strings
                t.tString = intern_string(&c, (x < 256) ? 1 : 2);
        }
        else if (currentbyte(file) == '(') {
                nextbyte(file);
                if (currentbyte(file) == '*') {
                        lexbufCnt = 0;
                        for (;;) {
                                nextbyte(file);
                                if (currentbyte(file) == '*') {
                                        nextbyte(file);
                                        if (currentbyte(file) == ')')
                                                break;
                                        BUF_APPEND(lexbuf, lexbufAlloc,
                                                   lexbufCnt, '*');
                                }
                                BUF_APPEND(lexbuf, lexbufAlloc,
                                           lexbufCnt, currentbyte(file));
                        }
                        nextbyte(file);
                        if (lexbufCnt > 0 && lexbuf[0] == '$') {
                                t.kind = TOK_DIRECTIVE;
                                t.tDirective = intern_string(lexbuf + 1,
                                                             lexbufCnt - 1);
                        }
                        else {
                                t.kind = TOK_COMMENTPAREN;
                                t.tComment = intern_string(lexbuf, lexbufCnt);
                        }
                }
                else {
                        t.kind = TOK_PARENLEFT;
                }
        }
        else if (currentbyte(file) == ')') {
                t.kind = TOK_PARENRIGHT;
                nextbyte(file);
        }
        else if (currentbyte(file) == '[') {
                t.kind = TOK_BRACKETLEFT;
                nextbyte(file);
        }
        else if (currentbyte(file) == ']') {
                t.kind = TOK_BRACKETRIGHT;
                nextbyte(file);
        }
        else if (currentbyte(file) == '+') {
                t.kind = TOK_PLUS;
                nextbyte(file);
        }
        else if (currentbyte(file) == '-') {
                t.kind = TOK_MINUS;
                nextbyte(file);
        }
        else if (currentbyte(file) == '*') {
                nextbyte(file);
                if (currentbyte(file) == ')') {
                        t.kind = TOK_DIRECTIVE;
                        nextbyte(file);
                }
                else {
                        t.kind = TOK_STAR;
                }
        }
        else if (currentbyte(file) == '/') {
                nextbyte(file);
                if (currentbyte(file) == '/') {
                        t.kind = TOK_COMMENTCXX;
                        for (;;) {
                                nextbyte(file);
                                if (!havebyte(file)
                                    || currentbyte(file) == '\n')
                                        break;
                        }
                }
                else {
                        t.kind = TOK_SLASH;
                }
                nextbyte(file);
        }
        else if (currentbyte(file) == '@') {
                t.kind = TOK_ATSIGN;
                nextbyte(file);
        }
        else if (currentbyte(file) == '^') {
                t.kind = TOK_CARET;
                nextbyte(file);
        }
        else if (currentbyte(file) == ':') {
                nextbyte(file);
                if (currentbyte(file) == '=') {
                        t.kind = TOK_ASSIGN;
                }
                else {
                        t.kind = TOK_COLON;
                }
                nextbyte(file);
        }
        else if (currentbyte(file) == '<') {
                nextbyte(file);
                if (currentbyte(file) == '=') {
                        t.kind = TOK_LE;
                }
                else if (currentbyte(file) == '>') {
                        t.kind = TOK_NE;
                }
                else {
                        t.kind = TOK_LT;
                }
                nextbyte(file);
        }
        else if (currentbyte(file) == '>') {
                nextbyte(file);
                if (currentbyte(file) == '=') {
                        t.kind = TOK_GE;
                }
                else {
                        t.kind = TOK_GT;
                }
                nextbyte(file);
        }
        else if (currentbyte(file) == '=') {
                t.kind = TOK_EQ;
                nextbyte(file);
        }
        else if (currentbyte(file) == ';') {
                t.kind = TOK_SEMICOLON;
                nextbyte(file);
        }
        else if (currentbyte(file) == ',') {
                t.kind = TOK_COMMA;
                nextbyte(file);
        }
        else if (currentbyte(file) == '.') {
                t.kind = TOK_DOT;
                nextbyte(file);
        }
        else if (isbytewhitespace(currentbyte(file))) {
                if (currentbyte(file) == '\r') {
                        nextbyte(file);
                        if (currentbyte(file) != '\n')
                                fatal("CR (0x0d) found, but it is not "
                                      "followed by NL (0x0a)");
                }
                nextbyte(file);
                while (havebyte(file) && isbytewhitespace(currentbyte(file)))
                        nextbyte(file);
                t.kind = TOK_WHITESPACE;
        }
        else if (currentbyte(file) == '{') {
                lexbufCnt = 0;
                for (;;) {
                        nextbyte(file);
                        if (currentbyte(file) == '}')
                                break;
                        BUF_APPEND(lexbuf, lexbufAlloc, lexbufCnt,
                                   currentbyte(file));
                }
                nextbyte(file);
                if (lexbufCnt > 0 && lexbuf[0] == '$') {
                        t.kind = TOK_DIRECTIVE;
                        t.tDirective = intern_string(lexbuf + 1, lexbufCnt - 1);
                }
                else {
                        t.kind = TOK_COMMENTBRACE;
                        t.tComment = intern_string(lexbuf, lexbufCnt);
                }
        }
        else {
                fatal("At %s %d: Failed to lex token (currentbyte %d)",
                      get_cstr(fileInfo[file].filepath),
                      bytePos[file],
                      currentbyte(file));
        }
        BUF_APPEND(token, tokenAlloc, tokenCnt, t);
        lastToken[file] = tokenCnt;
        return 1;
}


/***************************************************************************
 * DIRECTIVES
 **************************************************************************/

struct DirectiveInfo {
        int kind;  // DIRECTIVE_??
        String symstr;
        String keyword;
};

// populated at initialization time
static struct DirectiveInfo *directiveInfo;
static struct Alloc directiveInfoAlloc;
static int directiveInfoCnt;

// used only by init_directives()
void add_directiveInfo(int kind, const char *symstr, const char *keyword)
{
        directiveInfoCnt ++;
        assert(directiveInfoAlloc.cap >= directiveInfoCnt);
        BUF_RESERVE(directiveInfo, directiveInfoAlloc, directiveInfoCnt);
        directiveInfo[directiveInfoCnt - 1].kind = kind;
        directiveInfo[directiveInfoCnt - 1].symstr = intern_cstring(symstr);
        directiveInfo[directiveInfoCnt - 1].keyword = intern_cstring(keyword);
}

void init_directives(void)
{
        BUF_RESERVE(directiveInfo, directiveInfoAlloc, NUM_DIRECTIVES);
#define DIRECTIVEINFO(name) add_directiveInfo( DIRECTIVE_ ## name, "DIRECTIVE_" #name, #name );
        DIRECTIVEINFO( ALIGN );
        DIRECTIVEINFO( APPTYPE );
        DIRECTIVEINFO( ASSERTIONS );
        DIRECTIVEINFO( BOOLEVAL );
        DIRECTIVEINFO( CODEALIGN );
        DIRECTIVEINFO( DEBUGINFO );
        DIRECTIVEINFO( DEFINE );
        DIRECTIVEINFO( DENYPACKAGEUNIT );
        DIRECTIVEINFO( DESCRIPTION );
        DIRECTIVEINFO( DESIGNONLY );
        DIRECTIVEINFO( ELSE );
        DIRECTIVEINFO( ELSEIF );
        DIRECTIVEINFO( ENDIF );
        DIRECTIVEINFO( EXTENSION );
        DIRECTIVEINFO( OBJEXPORTALL );
        DIRECTIVEINFO( EXTENDEDSYNTAX );
        DIRECTIVEINFO( EXTENDEDCOMPATIBILITY );
        DIRECTIVEINFO( EXCESSPRECISION );
        DIRECTIVEINFO( HIGHCHARUNICODE );
        DIRECTIVEINFO( HINTS );
        DIRECTIVEINFO( IFDEF );
        DIRECTIVEINFO( IF );
        DIRECTIVEINFO( IFEND );
        DIRECTIVEINFO( IFNDEF );
        DIRECTIVEINFO( IFOPT );
        DIRECTIVEINFO( IMAGEBASE );
        DIRECTIVEINFO( IMPLICITBUILD );
        DIRECTIVEINFO( IMPORTEDDATA );
        DIRECTIVEINFO( INCLUDE );
        DIRECTIVEINFO( IOCHECKS );
        DIRECTIVEINFO( LIBPREFIX );
        DIRECTIVEINFO( LIBSUFFIX );
        DIRECTIVEINFO( LIBVERSION );
        DIRECTIVEINFO( LEGACYIFEND );
        DIRECTIVEINFO( LINK );
        DIRECTIVEINFO( LOCALSYMBOLS );
        DIRECTIVEINFO( LONGSTRINGS );
        DIRECTIVEINFO( MINSTACKSIZE );
        DIRECTIVEINFO( MAXSTACKSIZE );
        DIRECTIVEINFO( MESSAGE );
        DIRECTIVEINFO( METHODINFO );
        DIRECTIVEINFO( MINENUMSIZE );
        DIRECTIVEINFO( OLDTYPELAYOUT );
        DIRECTIVEINFO( OPENSTRINGS );
        DIRECTIVEINFO( OPTIMIZATION );
        DIRECTIVEINFO( OVERFLOWCHECKS );
        DIRECTIVEINFO( SETPEFLAGS );
        DIRECTIVEINFO( SETPEOPTFLAGS );
        DIRECTIVEINFO( SETPEOSVERSION );
        DIRECTIVEINFO( SETPESUBSYSVERSION );
        DIRECTIVEINFO( SETPEUSERVERSION );
        DIRECTIVEINFO( SAFEDIVIDE );
        DIRECTIVEINFO( POINTERMATH );
        DIRECTIVEINFO( RANGECHECKS );
        DIRECTIVEINFO( REALCOMPATIBILITY );
        DIRECTIVEINFO( REGION );
        DIRECTIVEINFO( ENDREGION );
        DIRECTIVEINFO( RESOURCE );
        DIRECTIVEINFO( RESOURCERESERVE );
        DIRECTIVEINFO( RTTI );
        DIRECTIVEINFO( RUNONLY );
        DIRECTIVEINFO( TYPEINFO );
        DIRECTIVEINFO( SCOPEDENUMS );
        DIRECTIVEINFO( STACKFRAMES );
        DIRECTIVEINFO( STRONGLINKTYPES );
        DIRECTIVEINFO( REFERENCEINFO );
        DIRECTIVEINFO( DEFINITIONINFO );
        DIRECTIVEINFO( TYPEADDRESS );
        DIRECTIVEINFO( UNDEF );
        DIRECTIVEINFO( VARSTRINGCHECKS );
        DIRECTIVEINFO( WARN );
        DIRECTIVEINFO( WARNINGS );
        DIRECTIVEINFO( WEAKPACKAGEUNIT );
        DIRECTIVEINFO( WEAKLINKRTTI );
        DIRECTIVEINFO( WRITEABLECONST );
        DIRECTIVEINFO( ZEROBASEDSTRINGS );
#undef DIRECTIVEINFO
}

/***************************************************************************
 * WORD LEXER
 **************************************************************************/
/* currently only used by directive parser */
String lex_word(const char *buf, int size)
{
        int i;
        for (i = 0; i < size; i++) {
                int c = buf[i];
                if (c < 'A' || 'Z' < c)
                        break;
        }
        return intern_string(buf, i);
}

/***************************************************************************
 * TOKEN STREAM ABSTRACTION
 **************************************************************************/
/* The fact that we parse the whole file in advance is hidden here. We should
 * not depend on it. */

int condStack[128];
int condStackSize;

int have_token(File file)
{
        return currentToken[file] < lastToken[file];
}

Token next_token(File file)
{
again:
        currentToken[file] ++;
        if (!have_token(file))
                fatal("No more tokens");

        switch (token[currentToken[file]].kind) {
        case TOK_WHITESPACE:
                goto again;
        case TOK_COMMENTCXX:
        case TOK_COMMENTBRACE:
        case TOK_COMMENTPAREN:
                /*
                printf("got comment: %s\n",
                       get_cstr(token[currentToken[file]].tComment));
                       */
                goto again;
        case TOK_DIRECTIVE: {
                String str;
                String kw;
                int i;
                int kwlen;
                str = token[currentToken[file]].tDirective;
                kw = lex_word(get_cstr(str), get_strlen(str));
                kwlen = get_strlen(kw);
                kw = intern_string(get_cstr(str), kwlen);
                for (i = 0; i < directiveInfoCnt; i++)
                        if (directiveInfo[i].keyword == kw)
                                break;
                if (i == directiveInfoCnt)
                        fatal("Unknown directive: %s\n", get_cstr(kw));

                if (directiveInfo[i].kind == DIRECTIVE_IFDEF) {
                        condStack[condStackSize++] = 0;
                }
                else if (directiveInfo[i].kind == DIRECTIVE_IFOPT) {
                        condStack[condStackSize++] = 0;
                }
                else if (directiveInfo[i].kind == DIRECTIVE_ELSE) {
                        condStack[condStackSize-1] = 1;  // for now always take else branch
                }
                else if (directiveInfo[i].kind == DIRECTIVE_ENDIF) {
                        if (condStackSize == 0)
                                fatal("ENDIF directive found, but there is no condition to end");
                        condStackSize --;
                }
                else {
                        printf("Unhandled directive %s\n", get_cstr(directiveInfo[i].symstr));
                }

                goto again;
        }
        default:
                break;
        }

        if (condStackSize > 0 && ! condStack[condStackSize - 1])
                goto again;

        return currentToken[file];
}

Token expect_token(File file, int kind)
{
        int t;
        t = currentToken[file];
        if (token[t].kind != kind)
                fatal("At %s:%d:%d: Unexpected %s token. Expected %s token.",
                      get_cstr(fileInfo[file].filepath), token[t].offset, 0,
                      tokInfo[token[t].kind].name, tokInfo[kind].name);
        next_token(file);
        return t;
}

int is_token(File file, int kind)
{
        return token[currentToken[file]].kind == kind;
}

int accept_token(File file, int kind)
{
        if (is_token(file, kind)) {
                next_token(file);
                return 1;
        }
        return 0;
}

/***************************************************************************
 * EXPRESSION PARSER
 **************************************************************************/

enum {
        OP_NOT,
        OP_POSITIVE,
        OP_NEGATIVE,
        OP_TAKEADDR,
        OP_SUBSCRIPT,
        OP_DEREF,
        OP_POWER,
        OP_ADD,
        OP_SUB,
        OP_MUL,
        OP_FDIV,
        OP_DIV,
        OP_MOD,
        OP_AND,
        OP_SHL,
        OP_SHR,
        OP_AS,
        OP_OR,
        OP_XOR,
        OP_EQ,
        OP_NE,
        OP_LT,
        OP_GT,
        OP_LE,
        OP_GE,
        NUM_OPS,
};

struct OpInfo {
        int prec;
        const char *name;
};

const struct OpInfo opInfo[NUM_OPS] = {
#define MAKE(p, op, str) [op] = { p, str }
        MAKE(6, OP_NOT,       "NOT"),
        MAKE(6, OP_POSITIVE,  "POSITIVE"),
        MAKE(6, OP_NEGATIVE,  "NEGATIVE"),
        MAKE(6, OP_TAKEADDR,  "TAKEADDR"),
        MAKE(7, OP_SUBSCRIPT, "SUBSCRIPT"),
        MAKE(7, OP_DEREF,     "DEREF"),
        MAKE(5, OP_POWER,     "POWER"),
        MAKE(4, OP_ADD,       "ADD"),
        MAKE(4, OP_SUB,       "SUB"),
        MAKE(5, OP_MUL,       "MUL"),
        MAKE(5, OP_FDIV,      "FDIV"),
        MAKE(5, OP_DIV,       "DIV"),
        MAKE(3, OP_MOD,       "MOD"),
        MAKE(3, OP_AND,       "AND"),
        MAKE(3, OP_SHL,       "SHL"),
        MAKE(3, OP_SHR,       "SHR"),
        MAKE(3, OP_AS,        "AS"),
        MAKE(3, OP_OR,        "OR"),
        MAKE(3, OP_XOR,       "XOR"),
        MAKE(3, OP_EQ,        "EQ"),
        MAKE(3, OP_NE,        "NE"),
        MAKE(3, OP_LT,        "LT"),
        MAKE(3, OP_GT,        "GT"),
        MAKE(3, OP_LE,        "LE"),
        MAKE(3, OP_GE,        "GE"),
#undef MAKE
};

enum {
        EXPR_LOAD,
        EXPR_IMMEDIATE,
        /* the only reason why we can't do only function calls is simplicity of
         * parsing: function reference expressions are necessarily output first,
         * while binary operators can not possibly be output first with our
         * parsing model. */
        EXPR_OP,
        EXPR_FUNCALL,
};

enum {
        VALUE_NUMBER,
        VALUE_STRING,
};

typedef struct {
        int kind;  // VALUE_??
        union {
                double tNumber;
                String tString;
        };
} Value;

Value makenumbervalue(double number)
{
        Value v;
        CLEAR(v);
        v.kind = VALUE_NUMBER;
        v.tNumber = number;
        return v;
}

Value makestringvalue(String string)
{
        Value v;
        CLEAR(v);
        v.kind = VALUE_STRING;
        v.tString = string;
        return v;
}

struct Expr {
        int kind;  // EXPR_??
        union {
                Value tValue;
                String tName;
                int tOp;  // unop/binop
                int tNargs;  // funcall
        };
};

int exprCnt;
struct Expr *expr;
struct Alloc exprAlloc;

void pushexpr(struct Expr x)
{
        BUF_RESERVE(expr, exprAlloc, exprCnt + 1);
        expr[exprCnt++] = x;
}

void makeload(String name)
{
        struct Expr x;
        CLEAR(x);
        x.kind = EXPR_LOAD;
        x.tName = name;
        pushexpr(x);
}

void makeimmediate(Value value)
{
        struct Expr x;
        CLEAR(x);
        x.kind = EXPR_IMMEDIATE;
        x.tValue = value;
        pushexpr(x);
}

void makeop(int op)
{
        struct Expr x;
        CLEAR(x);
        x.kind = EXPR_OP;
        x.tOp = op;
        pushexpr(x);
}

void makefuncall(int nargs)
{
        struct Expr x;
        CLEAR(x);
        x.kind = EXPR_FUNCALL;
        x.tNargs = nargs;
        pushexpr(x);
}

void parse_expr_recursive(File file, Scope scope, int prec)
{
        int op;
        int nargs;
        Symref ref;

        Token tok = currentToken[file];
        switch (token[tok].kind) {
        case TOK_PARENLEFT:
                next_token(file);
                parse_expr_recursive(file, scope, 0);
                expect_token(file, TOK_PARENRIGHT);
                break;
        case TOK_BRACKETLEFT:
                /* list literal */
                next_token(file);
                while (!is_token(file, TOK_BRACKETRIGHT)) {
                        parse_expr_recursive(file, scope, 1337 /* prec of comma */);
                        if (!accept_token(file, TOK_COMMA))
                                break;
                }
                expect_token(file, TOK_BRACKETRIGHT);
                break;
        case TOK_MINUS:
                next_token(file);
                parse_expr_recursive(file, scope, 1337);  /* prec of unary minus */
                makeop(OP_NEGATIVE);
                break;
        case TOK_ATSIGN:
                next_token(file);
                parse_expr_recursive(file, scope, 1337);
                makeop(OP_TAKEADDR);
                break;
        case TOK_KWNOT:
                next_token(file);
                parse_expr_recursive(file, scope, 1337);
                makeop(OP_NOT);
                break;  // return, assumption for now: not binds tightest
        case TOK_NAME:
                ref = add_scoped_symref(token[tok].tName, scope, tok);
                next_token(file);
                // XXX: see handling of postfix TOK_DOT below. That's where
                // this code belongs, but that code needs a way to get to the
                // referred symbol that we're parsing the relative member to.
                while (accept_token(file, TOK_DOT)) {
                        tok = expect_token(file, TOK_NAME);
                        ref = add_relative_symref(token[tok].tName, ref, tok);
                }
                makeload(ref);
                break;
        case TOK_NUMBER:
                makeimmediate(makenumbervalue(token[tok].tNumber));
                next_token(file);
                break;
        case TOK_STRING:
                makeimmediate(makestringvalue(token[tok].tString));
                next_token(file);
                while (token[currentToken[file]].kind == TOK_STRING)
                        // TODO
                        next_token(file);
                break;
        default:
                fatal("At %s:%d:%d: Unexpected %s token.",
                      get_cstr(fileInfo[file].filepath),
                      token[currentToken[file]].offset, 0,
                      tokInfo[token[currentToken[file]].kind].name);
        }
postfix:
        switch (token[currentToken[file]].kind) {
        case TOK_DOT:
                next_token(file);
                expect_token(file, TOK_NAME);
                /* TODO: op for member access */;
                goto postfix;
        case TOK_CARET:
                next_token(file);
                makeop(OP_DEREF);
                goto postfix;
        case TOK_PARENLEFT: goto funcall;
        case TOK_BRACKETLEFT: goto subscript;
        case TOK_PLUS:    op = OP_ADD; goto infix;
        case TOK_MINUS:   op = OP_SUB; goto infix;
        case TOK_STAR:    op = OP_MUL; goto infix;
        case TOK_SLASH:   op = OP_FDIV; goto infix;
        case TOK_KWDIV:   op = OP_DIV; goto infix;
        case TOK_KWAND:   op = OP_AND; goto infix;
        case TOK_KWOR:    op = OP_OR;  goto infix;
        case TOK_KWXOR:   op = OP_XOR; goto infix;
        case TOK_KWSHL:   op = OP_SHL; goto infix;
        case TOK_KWSHR:   op = OP_SHR; goto infix;
        case TOK_LT:      op = OP_LT;  goto infix;
        case TOK_LE:      op = OP_LE;  goto infix;
        case TOK_EQ:      op = OP_EQ;  goto infix;
        case TOK_NE:      op = OP_NE;  goto infix;
        case TOK_GE:      op = OP_GE;  goto infix;
        case TOK_GT:      op = OP_GT;  goto infix;
        default: return;
        }
        UNREACHABLE();
funcall:
        next_token(file);
        for (nargs = 0;; nargs++) {
                if (accept_token(file, TOK_PARENRIGHT))
                        break;
                if (nargs > 0)
                        expect_token(file, TOK_COMMA);
                parse_expr_recursive(file, scope, 0);
        }
        makefuncall(nargs);
        goto postfix;
subscript:
        next_token(file);
        parse_expr_recursive(file, scope, 0);
        expect_token(file, TOK_BRACKETRIGHT);
        makeop(OP_SUBSCRIPT);
        goto postfix;
infix:
        if (opInfo[op].prec < prec)
                return;
        next_token(file);
        parse_expr_recursive(file, scope, opInfo[op].prec);
        makeop(op);
        goto postfix;
}

void parse_expr(File file, Scope scope)
{
        parse_expr_recursive(file, scope, 0);
}

/***************************************************************************
 * STATEMENT PARSER
 **************************************************************************/

static void parse_stmt(File file, Scope scope);

static void parse_compound_stmt_inner(File file, Scope scope)
{
        for (;;) {
                /* I guess recognizing the end is best-effort. Maybe a general
                 * parse-compound-inner routine is not possible */
                if (is_token(file, TOK_KWEND))
                        break;
                if (is_token(file, TOK_KWEXCEPT))
                        break;
                parse_stmt(file, scope);
                if (!accept_token(file, TOK_SEMICOLON))
                        break;
        }
}

static void parse_begin_end_stmt(File file, Scope scope)
{
        expect_token(file, TOK_KWBEGIN);
        parse_compound_stmt_inner(file, scope);
        expect_token(file, TOK_KWEND);
}

static void parse_stmt(File file, Scope scope)
{
        if (is_token(file, TOK_KWBEGIN)) {
                parse_begin_end_stmt(file, scope);
        }
        else if (accept_token(file, TOK_KWIF)) {
                parse_expr(file, scope);
                expect_token(file, TOK_KWTHEN);
                parse_stmt(file, scope);
                if (accept_token(file, TOK_KWELSE))
                        parse_stmt(file, scope);
        }
        else if (accept_token(file, TOK_KWWHILE)) {
                parse_expr(file, scope);
                expect_token(file, TOK_KWDO);
                parse_stmt(file, scope);
        }
        else if (accept_token(file, TOK_KWFOR)) {
                expect_token(file, TOK_NAME);
                expect_token(file, TOK_ASSIGN);
                expect_token(file, TOK_NUMBER);
                expect_token(file, TOK_KWTO);
                parse_expr(file, scope);
                expect_token(file, TOK_KWDO);
                parse_stmt(file, scope);
        }
        else if (accept_token(file, TOK_KWTRY)) {
                parse_compound_stmt_inner(file, scope);
                if (accept_token(file, TOK_KWEXCEPT))
                        parse_compound_stmt_inner(file, scope);
                expect_token(file, TOK_KWEND);
        }
        else {  // assignment or function-call statement
                parse_expr(file, scope);
                if (accept_token(file, TOK_ASSIGN))
                        parse_expr(file, scope);
        }
}

/***************************************************************************
 * UNIT PARSER
 **************************************************************************/

Proctype parse_proctypeInfo(File file, Scope procheadscope, int isfunc);
Prochead parse_procedure_declaration(File file, Scope scope, int isfunc);

Type parse_type(File file, Scope scope)
{
        Token tok;
        String membername;
        Type type;

        if (accept_token(file, TOK_KWPROCEDURE)) {
                return parse_proctypeInfo(file, scope, 0);
        }
        else if (accept_token(file, TOK_KWFUNCTION)) {
                return parse_proctypeInfo(file, scope, 1);
        }
        else if (accept_token(file, TOK_KWRECORD) ||
                 accept_token(file, TOK_KWCLASS)) {
                Access access = ACCESS_PUBLIC;
                Record rec = recordCnt ++;
                while (!accept_token(file, TOK_KWEND)) {
                        if (accept_token(file, TOK_KWPUBLIC))
                                access = ACCESS_PUBLIC;
                        else if (accept_token(file, TOK_KWPRIVATE))
                                access = ACCESS_PRIVATE;
                        else if (accept_token(file, TOK_KWPROTECTED))
                                access = ACCESS_PROTECTED;
                        else if (accept_token(file, TOK_KWPROCEDURE))
                                // TODO: add member to record scope instead
                                // scope 0
                                parse_procedure_declaration(file, scope, 0);
                        else if (accept_token(file, TOK_KWFUNCTION))
                                // TODO: add member to record scope instead
                                // scope 0
                                parse_procedure_declaration(file, scope, 1);
                        else {  // var member
                                tok = expect_token(file, TOK_NAME);
                                membername = token[tok].tName;
                                expect_token(file, TOK_COLON);
                                type = parse_type(file, scope);
                                expect_token(file, TOK_SEMICOLON);
                                add_record_member(rec, membername, type, access);
                        }
                }
                return add_record_type(rec);
        }
        else if (accept_token(file, TOK_KWARRAY)) {
                expect_token(file, TOK_KWOF);
                type = parse_type(file, scope);
                // TODO: convert to array type
                return type;
        }
        else {
                while (accept_token(file, TOK_CARET))
                        continue;
                if (accept_token(file, TOK_KWCONST)) {
                        //while const is a keyword, in this case it's also a
                        //standalone type
                        return 0; //XXX
                }
                else {
                        tok = expect_token(file, TOK_NAME);
                        return 0; //XXX
                }
        }
}

void parse_type_declarations(File file, Scope scope)
{
        Token typenametoken;
        String typename;
        Type type;


        for (;;) {
                if (token[currentToken[file]].kind != TOK_NAME)
                        break;
                typenametoken = expect_token(file, TOK_NAME);
                typename = token[typenametoken].tName;
                expect_token(file, TOK_EQ);
                type = parse_type(file, scope);
                add_type_symbol(typename, scope, type, typenametoken);
                expect_token(file, TOK_SEMICOLON);
        }

        (void) typename;
}

void parse_const_declarations(File file, Scope scope)
{
        Token tok;
        String varname;
        Type type;

        for (;;) {
                if (token[currentToken[file]].kind != TOK_NAME)
                        break;
                tok = expect_token(file, TOK_NAME);
                varname = token[tok].tName;
                expect_token(file, TOK_COLON);
                type = parse_type(file, scope);
                add_const(varname, scope, type, tok);
                expect_token(file, TOK_EQ);
                parse_expr(file, scope);
                // TODO: add value
                expect_token(file, TOK_SEMICOLON);
        }
}

void parse_var_declarations(File file, Scope scope)
{
        Token tok;
        String varname;
        Type type;

        for (;;) {
                if (token[currentToken[file]].kind != TOK_NAME)
                        break;
                tok = expect_token(file, TOK_NAME);
                varname = token[tok].tName;
                while (accept_token(file, TOK_COMMA)) {
                        // TODO
                        printf("WARNING: parsing multiple comma-separated "
                               "variable names, but ignoring all "
                               "but the first (not yet supported)\n");
                        expect_token(file, TOK_NAME);
                }
                expect_token(file, TOK_COLON);
                type = parse_type(file, scope);
                expect_token(file, TOK_SEMICOLON);
                add_var(varname, scope, type, tok);
        }
}

void parse_label_declarations(File file, Scope scope)
{
        // TODO:
        while (!accept_token(file, TOK_SEMICOLON))
                next_token(file);
}

Proctype parse_proctypeInfo(File file, Scope procheadscope, int isfunc)
{
        Proctype proctype;
        Type proc_type;
        Token tok;
        int i;

        proctype = add_proctypeInfo(procheadscope);
        proc_type = add_proc_type(proctype);

        expect_token(file, TOK_PARENLEFT);
        for (i = 0;; i++) {
                String varname;
                Type vartype;
                if (accept_token(file, TOK_PARENRIGHT))
                        break;
                if (i > 0)
                        expect_token(file, TOK_SEMICOLON);

                int isconst = 0;
                if (accept_token(file, TOK_KWCONST))
                        isconst = 1;
                tok = expect_token(file, TOK_NAME);
                while (accept_token(file, TOK_COMMA)) {
                        // TODO
                        printf("WARNING: parsing multiple comma-separated "
                               "function argument names, but ignoring all "
                               "but the first (not yet supported)\n");
                        expect_token(file, TOK_NAME);
                }
                varname = token[tok].tName;
                expect_token(file, TOK_COLON);
                vartype = parse_type(file, procheadscope);
                //add_var(varname, scope, vartype, tok);
        }

        if (isfunc) {
                expect_token(file, TOK_COLON);
                Type returntype = parse_type(file, procheadscope);
                //XXX: still missing
                (void) returntype;
                //set_Prochead_returntype(p->ctx, proc, typename);
        }

        return proctype;
}

Prochead parse_prochead(File file, Scope parent, int isfunc)
{
        Token tok;
        String namespace;
        String procname;
        Prochead head;
        Scope scope;
        Type type;

        /* parse proc name and optional namespace */
        tok = expect_token(file, TOK_NAME);
        if (accept_token(file, TOK_DOT)) {
                namespace = token[tok].tName;
                tok = expect_token(file, TOK_NAME);
        } else {
                namespace = intern_cstring("");  // TODO "constant" empty
        }
        procname = token[tok].tName;

        head = procHeadCnt ++;
        scope = scopeCnt ++;
        type = parse_proctypeInfo(file, scope, isfunc);
        expect_token(file, TOK_SEMICOLON);

        BUF_RESERVE(procheadInfo, procHeadAlloc, procHeadCnt);
        procheadInfo[head].namespace = namespace;
        procheadInfo[head].name = procname;
        procheadInfo[head].type = type;
        procheadInfo[head].scope = scope;
        procheadInfo[head].parent = parent;
        procheadInfo[head].record = -1;

        add_proc_symbol(procname, parent, head, tok);

        BUF_RESERVE(scopeInfo, scopeInfoAlloc, scopeCnt);
        scopeInfo[scope].kind = SCOPE_PROCHEAD;
        scopeInfo[scope].tProchead = head;

        return head;
}

Prochead parse_procedure_declaration(File file, Scope scope, int isfunc)
{
        Prochead head = parse_prochead(file, scope, isfunc);
        for (;;) {
                if (accept_token(file, TOK_KWOVERLOAD)) {
                        expect_token(file, TOK_SEMICOLON);
                        //set_overload(p->ctx, proc);
                } else if (accept_token(file, TOK_KWINLINE)) {
                        expect_token(file, TOK_SEMICOLON);
                        //set_inline(p->ctx, proc);
                } else {
                        break;
                }
        }
        return head;
}

void parse_procedure_definition(File file, Scope parent, int isfunc)
{
        Prochead head = parse_prochead(file, parent, isfunc);

        if (accept_token(file, TOK_KWFORWARD)) {
                // change decision: it's only a declaration
                expect_token(file, TOK_SEMICOLON);
                return;
        }

        Procbody body = procBodyCnt ++;
        Scope scope = scopeCnt ++;

        BUF_RESERVE(procbodyInfo, procBodyAlloc, procBodyCnt);
        procbodyInfo[body].head = head;
        procbodyInfo[body].scope = scope;

        BUF_RESERVE(scopeInfo, scopeInfoAlloc, scopeCnt);
        scopeInfo[scope].kind = SCOPE_PROCBODY;
        scopeInfo[scope].tProcbody = body;

        for (;;) {
                if (accept_token(file, TOK_KWCONST))
                        parse_const_declarations(file, scope);
                else if (accept_token(file, TOK_KWVAR))
                        parse_var_declarations(file, scope);
                else if (accept_token(file, TOK_KWLABEL))
                        parse_label_declarations(file, scope);
                else if (is_token(file, TOK_KWBEGIN)) {
                        parse_begin_end_stmt(file, scope);
                        break;
                }
                else
                        fatal("Unexpected %s token.",
                              tokInfo[token[currentToken[file]].kind].name);
        }
        expect_token(file, TOK_SEMICOLON);
}

void parse_uses_declarations(File file, Unit unit, int isimpl)
{
        if (accept_token(file, TOK_KWUSES)) {
                for (;;) {
                        Token tok = expect_token(file, TOK_NAME);
                        while (accept_token(file, TOK_DOT)) {
                                // TODO
                                printf("WARNING: parsing multi-component unit "
                                       "name in uses declaration, but "
                                       "ignoring later components (not yet "
                                       "supported)\n");
                                expect_token(file, TOK_NAME);
                        }
                        String depname = token[tok].tName;

                        if (isimpl) {
                                implUsesCnt ++;
                                BUF_RESERVE(implUses, implUsesAlloc, implUsesCnt);
                                implUses[implUsesCnt-1].unit = unit;
                                implUses[implUsesCnt-1].depname = depname;
                        }
                        else {
                                ifaceUsesCnt ++;
                                BUF_RESERVE(ifaceUses, ifaceUsesAlloc, ifaceUsesCnt);
                                ifaceUses[ifaceUsesCnt-1].unit = unit;
                                ifaceUses[ifaceUsesCnt-1].depname = depname;
                        }

                        if (!accept_token(file, TOK_COMMA))
                                break;
                }
                expect_token(file, TOK_SEMICOLON);
        }
}

void parse_unit(Unit unit)
{
        Token tok;
        File file = unitInfo[unit].file;

        Scope ifaceScope = scopeCnt ++;
        BUF_RESERVE(scopeInfo, scopeInfoAlloc, scopeCnt);
        scopeInfo[ifaceScope].kind = SCOPE_INTERFACE;
        scopeInfo[ifaceScope].tUnit = unit;

        Scope implScope = scopeCnt ++;
        BUF_RESERVE(scopeInfo, scopeInfoAlloc, scopeCnt);
        scopeInfo[implScope].kind = SCOPE_IMPLEMENTATION;
        scopeInfo[implScope].tUnit = unit;

        //add_scope_parent(implScope, ifaceScope);
        unitInfo[unit].ifaceScope = ifaceScope;
        unitInfo[unit].implScope = implScope;

        printf("parsing unit %d: %s\n", unit,
                      get_cstr(fileInfo[unitInfo[unit].file].filepath));

        expect_token(file, TOK_KWUNIT);
        tok = expect_token(file, TOK_NAME);
        expect_token(file, TOK_SEMICOLON);

        if (token[tok].tName != unitInfo[unit].name) {
                fatal("While parsing unit %s: unit was defined as %s "
                      "but identifies itself as %s",
                      get_cstr(fileInfo[unitInfo[unit].file].filepath),
                      get_cstr(unitInfo[unit].name),
                      get_cstr(token[tok].tName));
        }

        expect_token(file, TOK_KWINTERFACE);
        parse_uses_declarations(file, unit, 0);
        for (;;) {
                if (accept_token(file, TOK_KWTYPE))
                        parse_type_declarations(file, ifaceScope);
                else if (accept_token(file, TOK_KWCONST))
                        parse_const_declarations(file, ifaceScope);
                else if (accept_token(file, TOK_KWVAR))
                        parse_var_declarations(file, ifaceScope);
                else if (accept_token(file, TOK_KWPROCEDURE))
                        parse_procedure_declaration(file, ifaceScope, 0);
                else if (accept_token(file, TOK_KWFUNCTION))
                        parse_procedure_declaration(file, ifaceScope, 1);
                else
                        break;
        }

        expect_token(file, TOK_KWIMPLEMENTATION);
        parse_uses_declarations(file, unit, 1);
        for (;;) {
                if (accept_token(file, TOK_KWTYPE))
                        parse_type_declarations(file, implScope);
                else if (accept_token(file, TOK_KWCONST))
                        parse_const_declarations(file, implScope);
                else if (accept_token(file, TOK_KWVAR))
                        parse_var_declarations(file, implScope);
                else if (accept_token(file, TOK_KWPROCEDURE))
                        parse_procedure_definition(file, implScope, 0);
                else if (accept_token(file, TOK_KWFUNCTION))
                        parse_procedure_definition(file, implScope, 1);
                else
                        break;
        }

        expect_token(file, TOK_KWEND);
        //XXX: is_token() because we currently can't read past the end!
        if (!is_token(file, TOK_DOT))
                fatal("Terminating 'end.' expected!");
}

/***************************************************************************
 * PROGRAM PARSER
 **************************************************************************/

String _extract_rightmost_dot_component(String fqname)
{
        int i;
        int n = 0;
        const char *s = get_cstr(fqname);
        for (i = 0; s[i]; i++)
                if (s[i] == '.')
                        n = i;
        return intern_string(s + n, strlen(s + n));
}

String _remove_rightmost_dot_component(String fqname)
{
        int i;
        int n = 0;
        const char *s = get_cstr(fqname);
        for (i = 0; s[i]; i++)
                if (s[i] == '.')
                        n = i;
        return intern_string(s, n);
}

static void parse_program(File file)
{
        Token tok;
        String pname;
        String uname;
        String pathspec;
        Program program;
        Scope scope;

        expect_token(file, TOK_KWPROGRAM);
        tok = expect_token(file, TOK_NAME);
        pname = token[tok].tName;
        expect_token(file, TOK_SEMICOLON);

        program = programCnt ++;
        scope = scopeCnt ++;

        BUF_RESERVE(programInfo, programInfoAlloc, programCnt);
        programInfo[program].fqname = pname;
        programInfo[program].name = _extract_rightmost_dot_component(pname);
        programInfo[program].project_default_namespace =
                                 _remove_rightmost_dot_component(pname);

        BUF_RESERVE(scopeInfo, scopeInfoAlloc, scopeCnt);
        scopeInfo[scope].kind = SCOPE_PROGRAM;
        scopeInfo[scope].tProgram = program;

        printf("parsing program %d: %s\n", program, get_cstr(pname));
        if (accept_token(file, TOK_KWUSES)) {
                for (;;) {
                        tok = expect_token(file, TOK_NAME);
                        uname = token[tok].tName;
                        expect_token(file, TOK_KWIN);
                        tok = expect_token(file, TOK_STRING);
                        pathspec = token[tok].tName;

                        programUsesCnt ++;

                        BUF_RESERVE(programUses, programUsesAlloc, programUsesCnt);
                        programUses[programUsesCnt-1].program = program;
                        programUses[programUsesCnt-1].depname = uname;
                        programUses[programUsesCnt-1].pathspec = pathspec;

                        if (accept_token(file, TOK_SEMICOLON))
                                break;
                        expect_token(file, TOK_COMMA);
                }
        }

        parse_begin_end_stmt(file, scope);

        //XXX: is_token() because we currently can't read past the end!
        if (!is_token(file, TOK_DOT))
                fatal("Terminating 'end.' expected!");
}


/***************************************************************************
 * Determine file, line, and column from given tokens
 **************************************************************************/
/* TODO: This is really slow. We should make it faster when it's more needed */

File get_file(Token tok)
{
        File file = 0;
        while (file < fileCnt && tok >= lastToken[file])
                file++;
        assert(file < fileCnt);
        return file;
}

int get_colno(Token tok)
{
        int i, n;
        File file = get_file(tok);
        int offset = token[tok].offset;

        i = offset - 1;
        n = 1;
        while (i > 0 && fileContents[file].buf[i] != '\n')
                i--, n ++;
        return n;
}


/***************************************************************************
 * SCOPE RESOLUTION
 **************************************************************************/

struct SymrefToResolve {
        int tryscope;  // scope where we look
        int symref;  // symbol that we are looking for
        int refscope;  // scope where the reference is
        int offset;  // offset in the file of the scope of the reference
};

int compare_Unit_by_name(const void *a, const void *b)
{
        const Unit *x = a;
        const Unit *y = b;
        return unitInfo[*x].name - unitInfo[*y].name;
}

int compare_SymbolInfo_by_scope(const void *a, const void *b)
{
        const struct SymbolInfo *x = a;
        const struct SymbolInfo *y = b;
        return x->scope - y->scope;
}

int compare_UnitUses_by_unit(const void *a, const void *b)
{
        const struct UnitUses *x = a;
        const struct UnitUses *y = b;
        return x->unit - y->unit;
}

Unit resolve_unit_dep(Unit unit, String depname)
{
        // XXX: implement namespace searching
        for (int i = 0; i < unitCnt; i++)
                if (unitInfo[i].name == depname)
                        return i;
        printf("WARNING: Unit %s: Ignoring unknown dependency '%s'\n",
               get_cstr(unitInfo[unit].name), get_cstr(depname));
        return UNITNOTFOUND;
}

/* returns Symbol, or SYMBOLNOTFOUND if not found */
Symbol search_scope(Scope scope, String name)
{
        for (int i = scopeInfo[scope].firstSymbol;
             i < scopeInfo[scope].lastSymbol;
             i++) {
                if (symbolInfo[i].name == name)
                        return i;
        }
        return SYMBOLNOTFOUND;
}

/* Resolve a single symref. Not sure if this one-by-one approach is a good
 * idea, but it's what we're doing for now. */
void resolve_symref(Symref ref)
{
        if (symrefInfo[ref].kind == SYMREF_RELATIVE) {
                Symref parent = symrefInfo[ref].tRelative.relativeTo;
                Type ptype = symrefInfo[parent].type;
                (void) parent;
                // can only do something if parent's type is resolved
                if (symrefInfo[parent].type == -1) {
                        String pstring = symrefInfo[parent].kind == SYMREF_SCOPE
                                ? symrefInfo[parent].tScope.name
                                : symrefInfo[parent].tRelative.name;
                        printf("ERROR: Type of parent of member %s.%s not resolved! Cannot continue\n",
                               get_cstr(pstring),
                               get_cstr(symrefInfo[ref].tRelative.name));
                        return;
                }
                if (ptype == 1337) {
                        printf("TODO!\n");
                        goto todoremoveme;
                }
                //printf("kind is %d\n", typeInfo[ptype].kind);
                if (typeInfo[ptype].kind == TYPE_BUILTIN) {
                        //nothing to do?
                }
                else if (typeInfo[ptype].kind != TYPE_RECORD) {
                        printf("Shouldn't happen: %d\n", typeInfo[ptype].kind);
                }
                else {
                        assert(typeInfo[ptype].kind == TYPE_RECORD);
                        Record rec = typeInfo[ptype].tRecord;
                        for (int i = recordInfo[rec].firstMember;
                             i < recordInfo[rec].lastMember; i++) {
                                if (recordMember[i].name ==
                                    symrefInfo[ref].tRelative.name) {
                                        symrefInfo[ref].type = recordMember[i].type;
                                        break;
                                }
                        }
                }
todoremoveme:
                /*printf("ERROR: Failed to resolve relative member %s\n",
                       get_cstr(symrefInfo[ref].tRelative.name));
                       */
                return;
        }

        assert(symrefInfo[ref].kind == SYMREF_SCOPE);

        /* It's a SYMREF_SCOPE symref, which means we have to resolve the
         * symbol by scope resolution. This is tricky, and probably not
         * correctly implemented yet. Also, if we add classes later, it will
         * get a lot trickier... */

        const Scope refScope = symrefInfo[ref].tScope.scope;
        const String searchName = symrefInfo[ref].tScope.name;
        Scope searchScope = refScope;
        //TODO: location in reference scope. Definition must be earlier
        Symbol found = SYMBOLNOTFOUND;

        for (;;) {
                int scopeKind = scopeInfo[searchScope].kind;

                found = search_scope(searchScope, searchName);
                if (found != SYMBOLNOTFOUND)
                        goto symrefResolved;

                if (scopeKind == SCOPE_PROGRAM) {
                        printf("TODO: resolve program sym refs\n");
                        break;
                }
                else if (scopeKind == SCOPE_INTERFACE) {
                        Unit unit = scopeInfo[searchScope].tUnit;
                        for (int j = unitInfo[unit].ifaceUsesFirst;
                             j < unitInfo[unit].ifaceUsesLast;
                             j++) {
                                found = search_scope(unitInfo[unit].implScope, searchName);
                                if (found != SYMBOLNOTFOUND)
                                        goto symrefResolved;
                        }
                        break;
                }
                else if (scopeKind == SCOPE_IMPLEMENTATION) {
                        // check iface scope, unit-uses, and impl-uses
                        Unit unit = scopeInfo[searchScope].tUnit;
                        found = search_scope(unitInfo[unit].ifaceScope,
                                             searchName);
                        if (found != SYMBOLNOTFOUND)
                                goto symrefResolved;
                        for (int j = unitInfo[unit].implUsesFirst;
                             j < unitInfo[unit].implUsesLast;
                             j++) {
                                found = search_scope(unitInfo[unit].implScope, searchName);
                                if (found != SYMBOLNOTFOUND)
                                        goto symrefResolved;
                        }
                        for (int j = unitInfo[unit].ifaceUsesFirst;
                             j < unitInfo[unit].ifaceUsesLast;
                             j++) {
                                found = search_scope(unitInfo[unit].ifaceScope, searchName);
                                if (found != SYMBOLNOTFOUND)
                                        goto symrefResolved;
                        }
                        break;
                }
                else if (scopeKind == SCOPE_PROCHEAD) {
                        Prochead head = scopeInfo[searchScope].tProchead;
                        searchScope = procheadInfo[head].parent;
                        /*
                        printf("parent of head is a %s scope\n",
                               scopeKindString[scopeInfo[searchScope].kind]);
                        printf("now try head's parent\n");
                        */
                }
                else if (scopeKind == SCOPE_PROCBODY) {
                        Procbody body = scopeInfo[searchScope].tProcbody;
                        assert(procbodyInfo[body].scope == searchScope);
                        Prochead head = procbodyInfo[body].head;
                        searchScope = procheadInfo[head].scope;
                        /*printf("parent of body is a %s scope\n",
                               scopeKindString[scopeInfo[searchScope].kind]);
                               */
                }
                else {
                        assert(0);
                }
        }

        if (found == SYMBOLNOTFOUND) {
                symrefInfo[ref].tScope.symbol = SYMBOLNOTFOUND;
                symrefInfo[ref].type = -1;
                //printf("NOT RESOLVED!!! %s\n", get_cstr(searchName));
        }
        else {
symrefResolved:
                symrefInfo[ref].tScope.symbol = found;
                // TODO: Check if it's the right kind of symbol
                Type type;
                switch (symbolInfo[found].kind) {
                case SYMBOL_UNIT:
                        printf("It's a unit!\n");
                        type = 1337;
                        break;
                case SYMBOL_TYPE:
                        printf("It's a type, and its type is $Type!\n");
                        type = 1337;
                        break;
                case SYMBOL_CONST:
                        type = constInfo[symbolInfo[found].tConst].type;
                        break;
                case SYMBOL_VAR:
                        type = varInfo[symbolInfo[found].tVar].type;
                        break;
                case SYMBOL_PROC:
                        type = procheadInfo[symbolInfo[found].tProc].type;
                        break;
                default:
                        printf("ERROR: don't know the type\n");
                        type = 1337;
                        break;
                }
                symrefInfo[ref].type = type;
                /*
                Scope defscope = symbolInfo[found].scope;
                printf("RESOLVED %d:%s to %d (%s, in %s)!\n", refScope,
                       get_cstr(symbolInfo[found].name),
                       found,
                       symbolKindString[symbolInfo[found].kind],
                       scopeKindString[scopeInfo[defscope].kind]);
                       */
        }
}

/***************************************************************************
 * MAIN DRIVER
 **************************************************************************/

void lex_and_add_tokens(File file)
{
        bytePos[file] = 0;
        lineNo[file] = 1;
        firstToken[file] = tokenCnt;
        while (lex_token(file))
                continue;
        lastToken[file] = tokenCnt;
        currentToken[file] = firstToken[file];
}

int main(int argc, const char **argv)
{
        if (argc != 2) {
                fprintf(stderr, "Usage: %s PROJECT.dpr\n", argv[0]);
                exit(1);
        }

        init_keywords();
        init_directives();
        init_builtin_types_and_symbols();

        dprFilepath = intern_cstring(argv[1]);
        File file = add_file(dprFilepath);
        read_file_contents(file);
        lex_and_add_tokens(file);
        parse_program(file);

        for (int i = 0; i < programUsesCnt; i++) {
                String pname = programInfo[programUses[i].program].fqname;
                String depname = programUses[i].depname;
                String pathspec = programUses[i].pathspec;

                printf("programUses %s %s '%s'\n",
                       get_cstr(pname),
                       get_cstr(depname),
                       get_cstr(pathspec));

                Unit unit = unitCnt ++;

                BUF_RESERVE(unitInfo, unitInfoAlloc, unitCnt);
                unitInfo[unit].fqname = depname;
                unitInfo[unit].name = _extract_rightmost_dot_component(depname);
                unitInfo[unit].namespace = _remove_rightmost_dot_component(depname);
                unitInfo[unit].file = add_file(pathspec);
        }

        for (int i = 0; i < unitCnt; i++) {
                file = unitInfo[i].file;
                read_file_contents(file);
                printf("size of %s is %d\n",
                       get_cstr(fileInfo[file].filepath),
                       fileContents[file].size);
        }

        for (int i = 0; i < unitCnt; i++) {
                file = unitInfo[i].file;
                lex_and_add_tokens(file);
                printf("tokens in %s: %d\n",
                       get_cstr(fileInfo[file].filepath),
                       lastToken[file] - firstToken[file]);
        }

        for (int i = 0; i < unitCnt; i++) {
                parse_unit(i);
        }

        /*
        int totalLineCount = 0;
        for (int i = 0; i < fileCnt; i++) {
                totalLineCount += lineNo[i];
        }
        printf("parsed %d files and %d lines\n", fileCnt, totalLineCount);
        */

        /* Sort symbols by scope. This is possible only before we resolve any
         * references. */
        //SORT(symbolInfo, symbolCnt, compare_SymbolInfo_by_scope);

        /* Find first-symbol and last-symbol values per scope. */
        for (int i = 0; i < scopeCnt; i++) {
                scopeInfo[i].firstSymbol = symbolCnt;
                scopeInfo[i].lastSymbol = 0;
        }
        for (int i = 0; i < symbolCnt; i++) {
                Scope scope = symbolInfo[i].scope;
                if (scopeInfo[scope].firstSymbol > i)
                        scopeInfo[scope].firstSymbol = i;
                if (scopeInfo[scope].lastSymbol < i + 1)
                        scopeInfo[scope].lastSymbol = i + 1;
        }

        /* Prepare implUses and ifaceUses */
        for (int i = 0; i < ifaceUsesCnt; i++) {
                Unit unit = ifaceUses[i].unit;
                String depname = ifaceUses[i].depname;
                ifaceUses[i].dep = resolve_unit_dep(unit, depname);
        }
        for (int i = 0; i < implUsesCnt; i++) {
                Unit unit = implUses[i].unit;
                String depname = implUses[i].depname;
                implUses[i].dep = resolve_unit_dep(unit, depname);
        }
        //SORT(ifaceUses, ifaceUsesCnt, compare_UnitUses_by_unit);
        //SORT(implUses, implUsesCnt, compare_UnitUses_by_unit);

        /* Find first-unit and last-unit values per uses-dependency */
        for (int i = 0; i < unitCnt; i++) {
                unitInfo[i].ifaceUsesFirst = ifaceUsesCnt;
                unitInfo[i].ifaceUsesLast = 0;
                unitInfo[i].implUsesFirst = implUsesCnt;
                unitInfo[i].implUsesLast = 0;
        }
        for (int i = 0; i < ifaceUsesCnt; i++) {
                if (unitInfo[ifaceUses[i].unit].ifaceUsesFirst > i)
                        unitInfo[ifaceUses[i].unit].ifaceUsesFirst = i;
                if (unitInfo[ifaceUses[i].unit].ifaceUsesLast < i + 1)
                        unitInfo[ifaceUses[i].unit].ifaceUsesLast = i + 1;
        }
        for (int i = 0; i < implUsesCnt; i++) {
                if (unitInfo[implUses[i].unit].implUsesFirst > i)
                        unitInfo[implUses[i].unit].implUsesFirst = i;
                if (unitInfo[implUses[i].unit].implUsesLast < i + 1)
                        unitInfo[implUses[i].unit].implUsesLast = i + 1;
        }

        /* Find first and last record members */
        BUF_RESERVE(recordInfo, recordInfoAlloc, recordCnt);
        for (int i = 0; i < recordCnt; i++) {
                recordInfo[i].firstMember = recordMemberCnt;
                recordInfo[i].lastMember = 0;
        }
        for (int i = 0; i < recordMemberCnt; i++) {
                if (recordInfo[recordMember[i].record].firstMember > i)
                        recordInfo[recordMember[i].record].firstMember = i;
                if (recordInfo[recordMember[i].record].lastMember < i + 1)
                        recordInfo[recordMember[i].record].lastMember = i + 1;
        }

        printf("number of strings: %d\n", stringCnt);

        /*
        for (int i = 0; i < symbolCnt; i++) {
                printf("definition of %s (%s) in scope %d \n",
                       get_cstr(symbolInfo[i].name),
                       symbolKindString[symbolInfo[i].kind],
                       symbolInfo[i].scope);
        }
        */

        /*
        for (int i = 0; i < symrefCnt; i++) {
        File file;
        int line;
        int col;
                file = get_file(symrefInfo[i].token);
                line = token[symrefInfo[i].token].lineno;
                col = get_colno(symrefInfo[i].token);
                printf("reference to %s from Scope %d at %s %d:%d\n",
                       get_cstr(symrefInfo[i].name),
                       symrefInfo[i].scope,
                       get_cstr(fileInfo[file].filepath), line, col);
        }
        */

        /*
        BUF_RESERVE(unitByName, unitByNameAlloc, unitCnt);
        for (int i = 0; i < unitCnt; i++)
                unitByName[i] = i;
        SORT(unitByName, unitCnt, compare_Unit_by_name);
        printf("all units:\n");
        for (int i = 0; i < unitCnt; i++)
                printf("%d %s\n",
                       unitByName[i],
                       get_cstr(unitInfo[unitByName[i]].name));
                       */

        for (int i = 0; i < symrefCnt; i++)
                resolve_symref(i);

        for (int i = 0; i < symrefCnt; i++) {
                if (symrefInfo[i].kind == SYMREF_SCOPE) {
                        if (symrefInfo[i].type == -1) {
                                String name = token[symrefInfo[i].token].tOrigname;
                                File file = get_file(symrefInfo[i].token);
                                String filepath = fileInfo[file].filepath;
                                int lineno = token[symrefInfo[i].token].lineno;
                                int colno = get_colno(symrefInfo[i].token);
                                printf("ERROR: Unresolved symbol "
                                       "%s at %s %d:%d\n",
                                       get_cstr(name),
                                       get_cstr(filepath),
                                       lineno, colno);
                        }
                } else {
                        assert(symrefInfo[i].kind == SYMREF_RELATIVE);
                        if (symrefInfo[i].type == -1)
                                printf("ERROR: Could not resolve member "
                                       ".%s at %s %d:%d\n",
                                       get_cstr(symrefInfo[i].tRelative.name),
                                       get_cstr(fileInfo[
                                                get_file(symrefInfo[i].token)
                                                ].filepath),
                                       token[symrefInfo[i].token].lineno,
                                       get_colno(symrefInfo[i].token));
                }
        }

        return 0;
}
