//

/*
Author:
   Steve Ruckdashel

Based on:
   Justin Cappos (jcappos@poly.edu)
   https://github.com/PolyPassHash/PolyPassHash/blob/master/python-reference-implementation/shamirsecret.py

Notes:
 - This module *intentionally* does not do hashing to detect incorrect
   shares.  For my application, I want them to get an (undetected) incorrect
   decoding if a share is wrong.

__author__ = 'Justin Cappos (jcappos@poly.edu)'
__version__ = '0.1'
__license__ = 'MIT'
__all__ = ['ShamirSecret']
*/
package sss

import (
	"bytes"
	"crypto/rand"
)

// This performs Shamir Secret Sharing operations in an incremental way
// that is useful for PolyPassHash.  It allows checking membership,
// genering shares one at a time, etc.
type Shamir struct {
	Threshold    int
	Secretdata   []byte
	coefficients []byte
}

// Creates an object.
// One must provide the threshold.
// If you want to have it create the coefficients, etc. call it with secret data
func New(threshold int, secretdata string) *Shamir {
	s := &Shamir{
		Threshold:    threshold,
		Secretdata:   []byte(secretdata),
		coefficients: nil,
	}

	return s
}

func (s *Shamir) Init() {
	// if we're given data, let's compute the random coefficients.   I do this
	// here so I can later iteratively compute the shares
	for _, secretbyte := range s.Secretdata {
		// this is the polynomial.   The first byte is the secretdata.
		// The next threshold-1 are (crypto) random coefficients
		// I'm applying Shamir's secret sharing separately on each byte.
		thesecoefficients := make([]byte, s.Threshold)
		thesecoefficients[0] = secretbyte
		rand.Read(thesecoefficients[1:])

		s.coefficients = append(s.coefficients, thesecoefficients...)
	}
}

type Share struct {
	X  int
	Fx []byte
}

// This validates that a share is correct given the secret data.
// It returns True if it is valid, False if it is not, and raises
// various errors when given bad data.
func (s *Shamir) IsValid(share Share) bool {
	if s.coefficients == nil {
		panic("Must initialize coefficients before checking is_valid_share")
	}

	if len(s.coefficients) != len(share.Fx) {
		panic("Must initialize coefficients before checking is_valid_share")
	}

	// let's just compute the right value
	correctshare := s.Compute(share.X)

	return bytes.Equal(share.Fx, correctshare.Fx)
}

// This computes a share, given x.   It returns a tuple with x and the
// individual f(x_0)f(x_1)f(x_2)... bytes for each byte of the secret.
// This raises various errors when given bad data.
func (s *Shamir) Compute(x int) *Share {
	if x <= 0 || x >= 255 {
		panic("In compute_share, x must be between 1 and 255, not: " + string(x))
	}
	if s.coefficients == nil {
		panic("Must initialize coefficients before computing a share")
	}
	sharebytes := []byte{}
	// go through the coefficients and compute f(x) for each value.
	// Append that byte to the share
	for _, thiscoefficient := range s.coefficients {
		thisshare := f(byte(x), thiscoefficient)
		sharebytes = append(sharebytes, thisshare)
	}

	return &Share{X: x, Fx: sharebytes}
}

// This recovers the secret data and coefficients given at least threshold
// shares.   Note, if any provided share does not decode, an error is
// raised.
func (s *Shamir) Recover(shares []Share) {
	// discard duplicate shares
	length := len(shares)
	for i := 0; i < length; i++ {
		for j := i + 1; j <= length; j++ {
			if shares[i].X == shares[j].X {
				shares[j] = shares[length]
				shares = shares[0:length]
				length--
				j--
			}
		}
	}

	if s.Threshold > len(shares) {
		panic("Threshold:" + string(s.Threshold) + " is smaller than the number of unique shares:" + string(len(shares)) + ".")
	}

	if s.Secretdata == nil {
		panic("Recovering secretdata when some is stored.   Use check_share instead.")
	}

	// the first byte of each share is the 'x'.
	xs := []byte{}
	for _, share := range shares {
		// the first byte should be unique...
		if bytes.IndexByte(xs, byte(share.X)) >= 0 {
			panic("Different shares with the same first byte! '" + string(share.X) + "'")
		}
		// ...and all should be the same length
		if len(share.Fx) != len(shares[0].Fx) {
			panic("Shares have different lengths!")
		}
		xs = append(xs, byte(share.X))
	}

	mycoefficients := []byte{}
	mysecretdata := []byte{}

	// now walk through each byte of the secret and do lagrange interpolation
	// to compute the coefficient...
	for byte_to_use := range shares[0].Fx {

		// we need to get the f(x)s from the appropriate bytes
		fxs := []byte{}
		for share := range shares {
			fxs = append(fxs, share[byte_to_use])
		}

		// build this polynomial
		resulting_poly := full_lagrange(xs, fxs)

		// If I have more shares than the threshold, the higher order coefficients
		// (those greater than threshold) must be zero (by Lagrange)...
		if !bytes.Equal(append(resulting_poly[:s.Threshold], make([]byte,len(shares)-s.Threshold)...),resulting_poly) {
			panic("Shares do not match.   Cannot decode")
		}

		// track this byte...
		mycoefficients = append(mycoefficients, resulting_poly...)

		mysecretdata = append(mysecretdata, resulting_poly[0])
	}

	// they check out!   Assign to the real ones!
	s.coefficients = mycoefficients

	s.Secretdata = mysecretdata
}
