// Private math helpers... Lagrange interpolation, polynomial math, etc.

package sss

// This actually computes f(x).  It's private and not needed elsewhere...
//
// This computes f(x) = a + bx + cx^2 + ...
// The value x is x in the above formula.
// The a, b, c, etc. bytes are the coefs_bytes in increasing order.
// It returns the result.
func f(x byte, coefs_bytes []byte) byte {
	if x == 0 {
		panic("invalid share index value, cannot be 0")
	}
	var accumulator byte = 0

	// start with x_i = 1.   We'll multiply by x each time around to increase it.
	var x_i byte = 1
	for _, c := range coefs_bytes {
		// we multiply this byte (a,b, or c) with x raised to the right power.
		accumulator = gf256_add(accumulator, gf256_mul(c, x_i))
		// raise x_i to the next power by multiplying by x.
		x_i = gf256_mul(x_i, x)
	}
	return accumulator
}

// This helper function takes two lists and 'multiplies' them.   I only tested
// the second list is of size <=2, but I don't think this matters.
//
// for example: [1,3,4] * [4,5] will compute (1 + 3x + 4x^2) * (4 - 5x) ->
// 4 + 17x + 31x^2 + 20x^3    or [4, 17, 31, 20]
// or at least, this would be the case if we weren't in GF256...
// in GF256, this is:
// 4 + 9x + 31x^2 + 20x^3    or [4, 9, 31, 20]
func multiply_polynomials(a, b []byte) []byte {

	// I'll compute each term separately and add them together
	resultterms := []byte{}

	// this grows to account for the fact the terms increase as it goes
	// for example, multiplying by x, shifts all 1 right
	termpadding := []byte{}
	for _, bterm := range b {
		thisvalue := termpadding[:]
		// multiply each a by the b term.
		for _, aterm := range a {
			thisvalue = append(thisvalue, gf256_mul(aterm, bterm))
		}

		resultterms = add_polynomials(resultterms, thisvalue)
		// moved another x value over...
		termpadding = append(termpadding,0)
	}

	return resultterms
}

// adds two polynomials together...
func add_polynomials(a, b []byte) []byte {

	// make them the same length...
	if len(a) < len(b) {
		a = append(a, make([]byte, len(b)-len(a))...)
	}
	if len(a) > len(b) {
		b = append(b, make([]byte, len(a)-len(b))...)
	}

	if len(a) != len(b) {
		panic("a and be are not the same length")
	}

	result := []byte{}
	for pos := range a {
		result = append(result, gf256_add(a[pos], b[pos]))
	}

	return result
}

// For lists containing xs and fxs, compute the full Lagrange basis polynomials.
// We want it all to populate the coefficients to check the shares by new
// share generation
func full_lagrange(xs, fxs []byte) []byte {
	if len(xs) != len(fxs) {
		panic("must be equal len")
	}

	returnedcoefficients := []byte{}
	// we need to compute:
	// l_0 =  (x - x_1) / (x_0 - x_1)   *   (x - x_2) / (x_0 - x_2) * ...
	// l_1 =  (x - x_0) / (x_1 - x_0)   *   (x - x_2) / (x_1 - x_2) * ...
	for i := range fxs {
		this_polynomial := []byte{1}
		// take the terms one at a time.
		// I'm computing the denominator and using it to compute the polynomial.
		for j := range fxs {
			// skip the i = jth term because that's how Lagrange works...
			if i == j {
				continue
			}

			// I'm computing the denominator and using it to compute the polynomial.
			denominator := gf256_sub(xs[i], xs[j])

			// don't need to negate because -x = x in GF256
			this_term := []byte{gf256_div(xs[j], denominator), gf256_div(1, denominator)}

			// let's build the polynomial...
			this_polynomial = multiply_polynomials(this_polynomial, this_term)
		}
		// okay, now I've gone and computed the polynomial.   I need to multiply it
		// by the result of f(x)

		this_polynomial = multiply_polynomials(this_polynomial, []byte{fxs[i]})

		// we've solved this polynomial.   We should add to the others.
		returnedcoefficients = add_polynomials(returnedcoefficients, this_polynomial)
	}

	return returnedcoefficients
}
