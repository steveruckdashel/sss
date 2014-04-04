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

import "os"

// This performs Shamir Secret Sharing operations in an incremental way 
// that is useful for PolyPassHash.  It allows checking membership,
// genering shares one at a time, etc.
type Shamir struct {
	Threshhold int
	Secretdata	[]byte
	coefficients []byte
}

// Creates an object.
// One must provide the threshold.
// If you want to have it create the coefficients, etc. call it with secret data
func New(threshold int, secretdata []byte) (*Shamir) {
	s := &Shamir{
		Threshhold: threshhold,
		Secretdata: secretdata,
		coefficients: []byte{},
	}
	
	for b := range secretdata {
		thesecoefficients := bytearray(secretbyte+os.urandom(threshold-1))
		
        s.coefficients = append(s.coefficients,thesecoefficients)
	}
	
	return s
}



/*
class ShamirSecret(object):

  def __init__(self, threshold, secretdata=None):
    """    
      """
    self.threshold=threshold
    self.secretdata=secretdata

    self._coefficients = None

    # if we're given data, let's compute the random coefficients.   I do this
    # here so I can later iteratively compute the shares
    if secretdata is not None:

      self._coefficients = []
      for secretbyte in secretdata:
        # this is the polynomial.   The first byte is the secretdata.   
        # The next threshold-1 are (crypto) random coefficients
        # I'm applying Shamir's secret sharing separately on each byte.
        thesecoefficients = bytearray(secretbyte+os.urandom(threshold-1))

        self._coefficients.append(thesecoefficients)



  def is_valid_share(self, share):
    """ This validates that a share is correct given the secret data.
        It returns True if it is valid, False if it is not, and raises
        various errors when given bad data.
        """

    # the share is of the format x, f(x)f(x)
    if type(share) is not tuple:
      raise TypeError("Share is of incorrect type: "+str(type(share)))

    if len(share) !=2:
      raise ValueError("Share is of incorrect length: "+str(share))

    
    if self._coefficients is None:
      raise ValueError("Must initialize coefficients before checking is_valid_share")
      
    if len(self._coefficients) != len(share[1]):
      raise ValueError("Must initialize coefficients before checking is_valid_share")
    
    x, fx = share

    # let's just compute the right value
    correctshare = self.compute_share(x)
    
    if correctshare == share:
      return True
    else:
      return False
    



    
  def compute_share(self, x):
    """ This computes a share, given x.   It returns a tuple with x and the
        individual f(x_0)f(x_1)f(x_2)... bytes for each byte of the secret.
        This raises various errors when given bad data.
        """

    if type(x) is not int:
      raise TypeError("In compute_share, x is of incorrect type: "+str(type(x)))

    if x<=0 or x>=256:
      raise ValueError("In compute_share, x must be between 1 and 255, not: "+str(x))

    if self._coefficients is None:
      raise ValueError("Must initialize coefficients before computing a share")
      
    sharebytes = bytearray()
    # go through the coefficients and compute f(x) for each value.   
    # Append that byte to the share
    for thiscoefficient in self._coefficients:
      thisshare = _f(x,thiscoefficient)
      sharebytes.append(thisshare)
    
    return (x,sharebytes)





  def recover_secretdata(self, shares):
    """ This recovers the secret data and coefficients given at least threshold
        shares.   Note, if any provided share does not decode, an error is 
        raised."""

    # discard duplicate shares
    newshares = []
    for share in shares:
      if share not in newshares:
        newshares.append(share)
    shares = newshares


    if self.threshold > len(shares):
      raise ValueError("Threshold:"+str(self.threshold)+" is smaller than the number of unique shares:"+str(len(shares))+".")

    if self.secretdata is not None:
      raise ValueError("Recovering secretdata when some is stored.   Use check_share instead.")

    # the first byte of each share is the 'x'.
    xs = []
    for share in shares:
      # the first byte should be unique...
      if share[0] in xs:
        raise ValueError("Different shares with the same first byte! '"+str(share[0])+"'")
      # ...and all should be the same length
      if len(share[1])!=len(shares[0][1]):
        raise ValueError("Shares have different lengths!")

      xs.append(share[0])
      

    mycoefficients = []
    mysecretdata = ''

    # now walk through each byte of the secret and do lagrange interpolation
    # to compute the coefficient...
    for byte_to_use in range(0,len(shares[0][1])):

      # we need to get the f(x)s from the appropriate bytes
      fxs = []
      for share in shares:
        fxs.append(share[1][byte_to_use])

      # build this polynomial
      resulting_poly = _full_lagrange(xs,fxs)


      # If I have more shares than the threshold, the higher order coefficients
      # (those greater than threshold) must be zero (by Lagrange)...
      if resulting_poly[:self.threshold] + [0]*(len(shares)-self.threshold) != resulting_poly:
        raise ValueError("Shares do not match.   Cannot decode")
      
      # track this byte...
      mycoefficients.append(bytearray(resulting_poly))
      
      mysecretdata += chr(resulting_poly[0])



    # they check out!   Assign to the real ones!
    self._coefficients = mycoefficients

    self.secretdata = mysecretdata

  
*/
