# tokenman

Simple Go library for generating and verifying JWT Tokens on top of `github.com/golang-jwt/jwt/v5`.

### install

    go get -u github.com/emicklei/tokenman

### usage

	tm, _ := NewTokenMan("your-signing-key")
	token, _ := tm.CreateToken("some-identity", 1) // TTL = 1 hour
	accessToken, _ := tm.VerifyToken(token)