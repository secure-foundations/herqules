Even with the memory safety patches applied, LowFat appears to report the following false positives:

## `444.namd`, `508.namd_r`

Known false-positive; see Duck and Yap 2016, section 6.1.

Standard output:
```
_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
        operation = escape (store)
        pointer   = 0xc054839e00 (heap)
        base      = 0xc0548399f0
        size      = 1040
        overflow  = +0

_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
        operation = escape (store)
        pointer   = 0xc08a2d8034 (heap)
        base      = 0xc08a2d7c10
        size      = 1040
        overflow  = +20
```

Original code; `Molecule.C`:
```
int Molecule::readfile(FILE *file) {
    char buf[1024];

    if ( ! fgets(buf,1024,file) || strcmp(buf,"MOLECULE_BEGIN\n") ) {
        printf("Missing MOLECULE_BEGIN\n");
        return -1;
    }

    if ( fscanf(file,"%d %d\n",&numAtoms,&numCalcExclusions) != 2 ) {
        printf("numAtoms read error\n");
        return -2;
    }

    ...
}
```

Decompiled code:
```
    v3 = *(_QWORD *)(8 * ((unsigned __int64)this >> 35) + 0x200000) * _R15;

    ...

    if ( fgets(buf, 1024, file) && !strcmp((const char *)&v46 - 0x10FFFFFF800LL, "MOLECULE_BEGIN\n") )
    {
        v60 = (int *)((char *)&this->numAtoms - v3);
        if ( (unsigned __int64)v60 >= *(_QWORD *)(8 * (v3 >> 35) + 0x200000) )
          lowfat_oob_warning(5u, &this->numAtoms, (const void *)v3);
        if ( (unsigned __int64)&this->numCalcExclusions - v3 >= *(_QWORD *)(8 * (v3 >> 3) + 0x200000) )
          lowfat_oob_warning(5u, &this->numCalcExclusions, (const void *)v3);
        if ( fscanf(file, "%d %d\n", &this->numAtoms, &this->numCalcExclusions) == 2 )

        ...
    }
```

## `450.soplex`

Known false-positive; see Duck and Yap 2016, section 6.1.

Standard output:
```
_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0xa0249eb5e0 (heap)
    base      = 0x706b6243a0
    size      = 272
    overflow  = +204971209008

_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0xa0249eb500 (heap)
    base      = 0x706b6243a0
    size      = 272
    overflow  = +204971208784

_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0xa0f3ca5860 (heap)
    base      = 0x70f5dee6a0
    size      = 272
    overflow  = +206123528368

_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0xa0f3ca5780 (heap)
    base      = 0x70f5dee6a0
    size      = 272
    overflow  = +206123528144
```

Original code; `svset.cc`, `islist.h`:
```
void SVSet::reMax(int newmax)
{
   list.move(set.reMax(newmax));
}

void IsList::move(ptrdiff_t delta)
{
  if (the_first)
  {
     T* elem;
     the_last  = reinterpret_cast<T*>(reinterpret_cast<char*>(the_last) + delta);
     the_first = reinterpret_cast<T*>(reinterpret_cast<char*>(the_first) + delta);
     for (elem = first(); elem; elem = next(elem))
        if (elem != last())
           elem->next() = reinterpret_cast<T*>(reinterpret_cast<char*>(elem->next()) + delta);
  }
}
```

Decompiled code:
```
    v9 = &this->list.the_last;
    v11 = *(_QWORD *)((char *)&loc_1FFFFA + 8 * (*v9 >> 35) + 6) * _R9;
    if ( soplex::DataSet<soplex::SVSet::DLPSV>::reMax(&this->set, newmax) + *v9 - v11 >= *(_QWORD *)((char *)&loc_1FFFFA + 8 * (v11 >> 35) + 6) )
    {
      lowfat_oob_warning(7u, v12, (const void *)v11);

      ...
    }
```

## `526.blender_r`

False positive; out-of-bounds reference is subsequently overwritten.

Standard output:
```
_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0x1707afd8040 (heap)
    base      = 0x1587afd8000
    size      = 32768
    overflow  = +103079182400

_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0x1707afd8040 (heap)
    base      = 0x1587afd8000
    size      = 32768
    overflow  = +103079182400
```

Original code; `polyfill2d.c`:
```
static void polyfill_prepare(PolyFill *pf, const float (*coords)[2], const unsigned int coords_tot, int coords_sign, unsigned int (*r_tris)[3], PolyIndex *r_indices) {
    ...

    if (coords_sign == 1) {
            for (i = 0; i < coords_tot; i++) {
                    indices[i].next = &indices[i + 1];
                    indices[i].prev = &indices[i - 1];
                    indices[i].index = i;
            }
    }
    else {
            /* reversed */
            unsigned int n = coords_tot - 1;
            for (i = 0; i < coords_tot; i++) {
                    indices[i].next = &indices[i + 1];
                    indices[i].prev = &indices[i - 1];
                    indices[i].index = (n - i);
            }
    }

    indices[0].prev = &indices[coords_tot - 1];
    indices[coords_tot - 1].next = &indices[0];

    ...
}
```

## `400.perlbench`

Known false-positive; see Duck and Yap 2016, section 6.1.

Standard output:
```
_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0x8dc9a58df (heap)
    base      = 0x8dc9a58e0
    size      = 16
    underflow = -1

_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0x8dc9a58e0 (heap)
    base      = 0x8dc9a58d0
    size      = 16
    overflow  = +0
```

Original code; `regcomp.c`:
```
STATIC regnode *
S_regbranch(pTHX_ RExC_state_t *pRExC_state, I32 *flagp, I32 first)
{
    ...

    RExC_parse--;

    ...
}

STATIC char*
S_nextchar(pTHX_ RExC_state_t *pRExC_state)
{
    char* retval = RExC_parse++;

    ...
}
```

## `403.gcc`

Known false-positive; see Duck and Yap 2016, section 6.1.

Standard output:
```
_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0x178b4bffe58 (heap)
    base      = 0x178b4c00000
    size      = 524288
    underflow = -424

_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0x16086beffcb (heap)
    base      = 0x16086bf0000
    size      = 65536
    underflow = -53
```

Original code; `alias.c`:
```
void init_alias_analysis () {
    ...

    reg_known_value = (rtx *) xcalloc ((maxreg - FIRST_PSEUDO_REGISTER), sizeof (rtx)) - FIRST_PSEUDO_REGISTER;
    reg_known_equiv_p = (char*) xcalloc ((maxreg - FIRST_PSEUDO_REGISTER), sizeof (char)) - FIRST_PSEUDO_REGISTER;
    ...
}
```

## `500.perlbench_r`, `600.perlbench_s`

False positive.

Standard output:
```
_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (store)
    pointer   = 0x1002de3bbf0 (heap)
    base      = 0x1002de3bc00
    size      = 3584
    underflow = -16
```

Original code; `sv.c`:
```
#define SvANY(sv)   (sv)->sv_any

#define new_body_allocated(sv_type)     \
    (void *)((char *)S_new_body(aTHX_ sv_type)  \
         - bodies_by_type[sv_type].offset)

#define new_XPVNV() new_body_allocated(SVt_PVNV)

void Perl_init_constants(pTHX) {
    ...

    SvANY(&PL_sv_no) = new_XPVNV();

    ...
}

void Perl_sv_upgrade(pTHX_ SV *const sv, svtype new_type) {
    ...

    SvANY(sv) = new_body;

    ...
}
```

## `525.x264_r`, `625.x264_s`:

False positive; out-of-bounds prefetch has no effect.

Standard output:
```
_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (call)
    pointer   = 0x170ee37fb1c (heap)
    base      = 0x170ee380000
    size      = 262144
    underflow = -1252

_|                                      _|_|_|_|            _|
_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|

LOWFAT WARNING: out-of-bounds error detected!
    operation = escape (call)
    pointer   = 0x170ee37fb30 (heap)
    base      = 0x170ee380000
    size      = 262144
    underflow = -1232
```

Original code; `macroblock.c`:
```
#define x264_prefetch(x) __builtin_prefetch(x)

void x264_macroblock_cache_load( x264_t *h, int mb_x, int mb_y )
{
    ...

    int top_y = mb_y - (1 << h->mb.b_interlaced);
    int top_4x4 = (4*top_y+3) * h->mb.i_b4_stride + 4*mb_x;

    ...

            for( int l = 0; l < (h->sh.i_type == SLICE_TYPE_B) + 1; l++ )
            {
                x264_prefetch( &h->mb.mv[l][top_4x4-1] );
                /* Top right being not in the same cacheline as top left will happen
                 * once every 4 MBs, so one extra prefetch is worthwhile */
                x264_prefetch( &h->mb.mv[l][top_4x4+4] );
                x264_prefetch( &h->mb.ref[l][top_8x8-1] );
                x264_prefetch( &h->mb.mvd[l][top] );
            }

    ...
}
```

Decompiled code:
```
        _RBX = *v129 + 4LL * (v467 - 1);
        __asm { mulx    rdx, rcx, [r15+rax*8+100000h] }
        v134 = *(_QWORD *)((char *)&loc_1FFFFA + 8 * (*v129 >> 35) + 6) * _RDX;
        if ( _RBX - v134 >= *(_QWORD *)((char *)&loc_1FFFFA + 8 * (v134 >> 35) + 6) )
          lowfat_oob_warning();
        __asm { prefetcht0 byte ptr [rbx] }

```
