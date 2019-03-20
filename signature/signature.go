// Package signature provides wrapper types around public key signatures.
package signature

import (
	"bytes"
	"crypto/sha512"
	"encoding"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ed25519"
)

const (
	// PublicKeySize is the size of a public key in bytes.
	PublicKeySize = ed25519.PublicKeySize

	// PrivateKeySize is the size of a private key in bytes.
	PrivateKeySize = ed25519.PrivateKeySize

	// SignatureSize is the size of a signature in bytes.
	SignatureSize = ed25519.SignatureSize

	privPEMType = "ED25519 PRIVATE KEY"
	pubPEMType  = "ED25519 PUBLIC KEY"

	filePerm = 0600
)

var (
	// ErrMalformedPublicKey is the error returned when a public key is
	// malformed.
	ErrMalformedPublicKey = errors.New("signature: malformed public key")

	// ErrMalformedSignature is the error returned when a signature is
	// malformed.
	ErrMalformedSignature = errors.New("signature: malformed signature")

	// ErrMalformedPrivateKey is the error returned when a private key is
	// malformed.
	ErrMalformedPrivateKey = errors.New("signature: malformed private key")

	// ErrPublicKeyMismatch is the error returned when a signature was
	// not produced by the expected public key.
	ErrPublicKeyMismatch = errors.New("signature: public key mismatch")

	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("signature: protobuf is nil")

	// ErrVerifyFailed is the error return when a signature verification
	// fails when opening a signed blob.
	ErrVerifyFailed = errors.New("signed: signature verification failed")

	errNilPEM          = errors.New("signature: PEM data missing blocks")
	errTrailingGarbage = errors.New("signature: PEM data has trailing garbage")
	errMalformedPEM    = errors.New("signature: malformed PEM")

	errKeyMismatch = errors.New("signature: public key PEM is not for private key")

	_ encoding.BinaryMarshaler   = PublicKey{}
	_ encoding.BinaryUnmarshaler = (*PublicKey)(nil)
	_ encoding.BinaryMarshaler   = RawSignature{}
	_ encoding.BinaryUnmarshaler = (*RawSignature)(nil)
	_ encoding.BinaryUnmarshaler = (*PrivateKey)(nil)
)

// MapKey is a PublicKey as a fixed sized byte array for use as a map key.
type MapKey [PublicKeySize]byte

// String returns a string representation of the MapKey.
func (k MapKey) String() string {
	return hex.EncodeToString(k[:])
}

// PublicKey is a public key used for signing.
type PublicKey ed25519.PublicKey

// Verify returns true iff the signature is valid for the public key
// over the message.
func (k PublicKey) Verify(message, sig []byte) bool {
	if len(k) != PublicKeySize {
		return false
	}
	if len(sig) != SignatureSize {
		return false
	}

	data, err := digest(message)
	if err != nil {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(k), data, sig)
}

// MarshalBinary encodes a public key into binary form.
func (k PublicKey) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, k[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled public key.
func (k *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return ErrMalformedPublicKey
	}

	if len(*k) != PublicKeySize {
		keybuf := make([]byte, PublicKeySize)
		*k = keybuf
	}
	copy((*k)[:], data)

	return nil
}

// UnmarshalPEM decodes a PEM marshaled PublicKey.
func (k *PublicKey) UnmarshalPEM(data []byte) error {
	b, err := unmarshalPEM(pubPEMType, data)
	if err != nil {
		return err
	}

	return k.UnmarshalBinary(b)
}

// MarshalPEM encodes a PublicKey into PEM form.
func (k PublicKey) MarshalPEM() (data []byte, err error) {
	return marshalPEM(pubPEMType, k[:])
}

// UnmarshalHex deserializes a hexadecimal text string into the given type.
func (k *PublicKey) UnmarshalHex(text string) error {
	if text[0:2] == "0x" {
		text = text[2:]
	}
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return k.UnmarshalBinary(b)
}

// Equal compares vs another public key for equality.
func (k PublicKey) Equal(cmp PublicKey) bool {
	return bytes.Equal(k, cmp)
}

// String returns a string representation of the public key.
func (k PublicKey) String() string {
	hexKey := hex.EncodeToString(k)

	if len(k) != PublicKeySize {
		return "[malformed]: " + hexKey
	}

	return hexKey
}

// ToMapKey returns a fixed-sized representation of the public key.
func (k PublicKey) ToMapKey() MapKey {
	if len(k) != PublicKeySize {
		panic("signature: public key invalid size for ID")
	}

	var mk MapKey
	copy(mk[:], k)

	return mk
}

// LoadPEM loads a public key from a PEM file on disk.  Iff the public key
// is missing and a private key is provided, the private key's corresponding
// public key will be written and loaded.
func (k *PublicKey) LoadPEM(fn string, priv *PrivateKey) error {
	f, err := os.Open(fn) // nolint: gosec
	if err != nil {
		if os.IsNotExist(err) && priv != nil {
			pubKey := priv.Public()

			var buf []byte
			if buf, err = pubKey.MarshalPEM(); err != nil {
				return err
			}

			copy((*k)[:], pubKey[:])

			return ioutil.WriteFile(fn, buf, filePerm)
		}
		return err
	}
	defer f.Close() // nolint: errcheck

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	if err = k.UnmarshalPEM(buf); err != nil {
		return err
	}

	if priv != nil && !k.Equal(priv.Public()) {
		return errKeyMismatch
	}

	return nil
}

// RawSignature is a raw signature.
type RawSignature [SignatureSize]byte

// MarshalBinary encodes a signature into binary form.
func (r RawSignature) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, r[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled signature.
func (r *RawSignature) UnmarshalBinary(data []byte) error {
	if len(data) != SignatureSize {
		return ErrMalformedSignature
	}

	copy(r[:], data)

	return nil
}

// PrivateKey is a private key used for signing.
type PrivateKey ed25519.PrivateKey

// Sign generates a signature with the private key over the message.
func (k PrivateKey) Sign(message []byte) ([]byte, error) {
	data, err := digest(message)
	if err != nil {
		return nil, err
	}

	return ed25519.Sign(ed25519.PrivateKey(k), data), nil
}

// Public returns the PublicKey corresponding to k.
func (k PrivateKey) Public() PublicKey {
	return PublicKey(ed25519.PrivateKey(k).Public().(ed25519.PublicKey))
}

// String returns the string representation of a PrivateKey.
func (k PrivateKey) String() string {
	// There is close to zero reason to ever serialize a PrivateKey
	// to a string in this manner.  This method exists as a safeguard
	// against inadvertently trying to do so (eg: misguided attempts
	// at logging).
	return "[redacted private key]"
}

// UnmarshalBinary decodes a binary marshaled private key.
func (k *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return ErrMalformedPrivateKey
	}

	if len(*k) != PrivateKeySize {
		keybuf := make([]byte, PrivateKeySize)
		*k = keybuf
	}
	copy((*k)[:], data)

	return nil
}

// UnmarshalPEM decodes a PEM marshaled PrivateKey.
func (k *PrivateKey) UnmarshalPEM(data []byte) error {
	b, err := unmarshalPEM(privPEMType, data)
	if err != nil {
		return err
	}

	return k.UnmarshalBinary(b)
}

// MarshalPEM encodes a PrivateKey into PEM form.
func (k PrivateKey) MarshalPEM() (data []byte, err error) {
	return marshalPEM(privPEMType, k[:])
}

// LoadPEM loads a private key from a PEM file on disk.  Iff the private
// key is missing and an entropy source is provided, a new private key
// will be generated and written.
func (k *PrivateKey) LoadPEM(fn string, rng io.Reader) error {
	f, err := os.Open(fn) // nolint: gosec
	if err != nil {
		if os.IsNotExist(err) && rng != nil {
			if err = k.generate(rng); err != nil {
				return err
			}

			var buf []byte
			buf, err = k.MarshalPEM()
			if err != nil {
				return err
			}

			return ioutil.WriteFile(fn, buf, filePerm)
		}
		return err
	}
	defer f.Close() // nolint: errcheck

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	fm := fi.Mode()
	if fm.Perm() != filePerm {
		return fmt.Errorf("signature: file '%s' has invalid permissions: %v", fn, fm.Perm())
	}

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	return k.UnmarshalPEM(buf)
}

func (k *PrivateKey) generate(rng io.Reader) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rng, seed); err != nil {
		return err
	}

	nk := ed25519.NewKeyFromSeed(seed)
	_ = k.UnmarshalBinary(nk[:])

	return nil
}

// NewPrivateKey generates a new private key via the provided
// entropy source.
func NewPrivateKey(rng io.Reader) (k PrivateKey, err error) {
	err = k.generate(rng)
	return
}

func digest(message []byte) ([]byte, error) {
	h := sha512.New512_256()
	_, _ = h.Write(message)
	sum := h.Sum(nil)

	return sum[:], nil
}

func unmarshalPEM(pemType string, data []byte) ([]byte, error) {
	blk, rest := pem.Decode(data)
	if blk == nil {
		return nil, errNilPEM
	}
	if len(rest) != 0 {
		return nil, errTrailingGarbage
	}
	if blk.Type != pemType {
		return nil, errMalformedPEM
	}

	return blk.Bytes, nil
}

func marshalPEM(pemType string, data []byte) ([]byte, error) {
	blk := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, blk); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
