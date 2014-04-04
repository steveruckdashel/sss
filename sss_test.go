package sss

import "testing"

/*
Example:
  import shamirsecret
  # create a new object with some secret...
  mysecret = shamirsecret.ShamirSecret(2, 'my shared secret')
  # get shares out of it...

  a = mysecret.compute_share(4)
  b = mysecret.compute_share(6)
  c = mysecret.compute_share(1)
  d = mysecret.compute_share(2)

  # Recover the secret value
  newsecret = shamirsecret.ShamirSecret(2)

  newsecret.recover_secretdata([a,b,c])  # note, two would do...

  # d should be okay...
  assert(newsecret.is_valid_share(d))

  # change a byte
  d[1][3] = d[1][3] - 1

  # but not now...
  assert(newsecret.is_valid_share(d) is False)
*/

func TestSss(t *testing.T) {
	mysecret := Shamir.Secret(2, "my shared secret")

	a := mysecret.Share(4)
	b := mysecret.Share(6)
	c := mysecret.Share(1)
	d := mysecret.Share(2)

	newsecret := Shamir.Secret(2)
	newsecret.Recover(a, b, c)
	if !newsecret.ValidShare(d) {
		t.Logf("(%v) was an invalid share", d)
		t.Fail()
	}

	d[1][3] = d[1][3] - 1

	if newsecret.ValidShare(d) {
		t.Logf("(%v) was a valid share", d)
		t.Fail()
	}
}
