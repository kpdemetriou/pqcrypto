#include "poly.h"

void poly_lift(poly *r, const poly *a) {
    int i;
    for (i = 0; i < NTRU_N; i++) {
        r->coeffs[i] = a->coeffs[i];
    }
    poly_Z3_to_Zq(r);
}


