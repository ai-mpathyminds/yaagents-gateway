// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// Command benchtoken generates a long-lived HS256 JWT for the bench harness.
// The token is valid for the configured expiry (-exp seconds from now) and
// carries minimal claims suitable for the tokenvalidator plugin in test_mode.
//
// Usage: go run ./bench/cmd/benchtoken -secret <secret> -subject <sub> -exp <seconds>
// Output: the raw JWT string (stdout); use: BENCH_TOKEN="$(go run ./bench/cmd/benchtoken ...)"
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	secret := flag.String("secret", "bench-secret", "HS256 signing secret")
	subject := flag.String("subject", "bench-user", "JWT sub claim")
	expSec := flag.Int("exp", 3600, "token validity in seconds from now")
	flag.Parse()

	claims := jwt.MapClaims{
		"sub":  *subject,
		"iss":  "bench-harness",
		"exp":  time.Now().Add(time.Duration(*expSec) * time.Second).Unix(),
		"iat":  time.Now().Unix(),
		"aud":  "bench-gateway",
		// role claim accepted by tokenvalidator for bench load profile
		"roles": []string{"bench"},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(*secret))
	if err != nil {
		log.Fatalf("benchtoken: sign: %v", err)
	}
	fmt.Println(signed)
}
