// SPDX-License-Identifier: BSD-3-Clause

package main

import "golang.org/x/crypto/ssh"

type sshPublicKey = ssh.PublicKey

func parseAuthorizedKey(b []byte) (ssh.PublicKey, string, []string, []byte, error) {
	return ssh.ParseAuthorizedKey(b)
}
