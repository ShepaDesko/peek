package branding

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Sanitising what an administrator uploads.
//
// Custom CSS and an uploaded logo are the two places where text chosen by a
// person ends up in every visitor's browser. An administrator is trusted, but
// not infinitely: an account that is taken over must not be able to turn the
// recipient page into an exfiltration channel, and the rules below are what
// stop that.

// MaxCustomCSSBytes bounds the stylesheet. A brand needs a few rules; a
// hundred kilobytes of CSS is something else.
const MaxCustomCSSBytes = 16 << 10

// MaxAssetBytes bounds an uploaded image.
const MaxAssetBytes = 512 << 10

// Errors returned when something is refused.
var (
	ErrCSSTooLarge   = fmt.Errorf("custom CSS is limited to %d KiB", MaxCustomCSSBytes/1024)
	ErrCSSForbidden  = errors.New("custom CSS may not load anything from outside this instance")
	ErrAssetTooLarge = fmt.Errorf("an image is limited to %d KiB", MaxAssetBytes/1024)
	ErrAssetType     = errors.New("only PNG, WebP, SVG and ICO images are accepted")
	ErrAssetInvalid  = errors.New("that file is not a readable image")
)

var cssCommentPattern = regexp.MustCompile(`(?s)/\*.*?\*/`)

// forbiddenCSS are the constructs that would let a stylesheet reach outside
// this origin, or run something.
//
//   - @import pulls in another stylesheet, from anywhere;
//   - url() fetches an image, a font or a cursor, and the request itself is
//     the leak — a background on the reveal page would tell a third party that
//     a secret was opened, and when;
//   - expression() and behavior: are old Internet Explorer script hooks;
//   - javascript: speaks for itself.
var forbiddenCSS = []string{
	"@import",
	"url(",
	"expression(",
	"behavior:",
	"-moz-binding",
	"javascript:",
	"</style",
	"@charset",
	"@namespace",
}

// CheckCSS validates custom CSS and returns it unchanged when it is accepted.
//
// It refuses rather than strips: silently removing half an administrator's
// stylesheet produces a brand nobody can explain, while a refusal names the
// construct and the reason.
func CheckCSS(css string) (string, error) {
	css = strings.TrimSpace(css)
	if css == "" {
		return "", nil
	}
	if len(css) > MaxCustomCSSBytes {
		return "", ErrCSSTooLarge
	}
	if !utf8.ValidString(css) {
		return "", errors.New("custom CSS must be valid UTF-8")
	}

	// Comments are stripped before the check so that /* url( */ cannot hide a
	// construct from us, and a comment cannot smuggle one past either.
	probe := strings.ToLower(cssCommentPattern.ReplaceAllString(css, " "))
	// CSS lets any character be written as a backslash escape, so "@9 mport"
	// is "@import" to a browser. Decode those first, then drop whatever
	// backslashes remain, so neither form slips through.
	probe = decodeCSSEscapes(probe)
	probe = strings.ReplaceAll(probe, "\\", "")
	for _, forbidden := range forbiddenCSS {
		if strings.Contains(probe, forbidden) {
			return "", fmt.Errorf("%w (found %q)", ErrCSSForbidden, forbidden)
		}
	}
	return css, nil
}

var cssEscapePattern = regexp.MustCompile(`\\([0-9a-f]{1,6})[ 	
]?`)

// decodeCSSEscapes turns backslash-hex escapes into the characters they mean,
// which is what a browser does before it reads a rule.
func decodeCSSEscapes(css string) string {
	return cssEscapePattern.ReplaceAllStringFunc(css, func(match string) string {
		groups := cssEscapePattern.FindStringSubmatch(match)
		if len(groups) != 2 {
			return match
		}
		var value int64
		for _, c := range groups[1] {
			var digit int64
			switch {
			case c >= '0' && c <= '9':
				digit = int64(c - '0')
			case c >= 'a' && c <= 'f':
				digit = int64(c-'a') + 10
			default:
				return match
			}
			value = value*16 + digit
		}
		if value <= 0 || value > 0x10FFFF {
			return match
		}
		return string(rune(value))
	})
}

// SanitizeCSS returns the stylesheet when it passes, and nothing when it does
// not. Used on the serving path, where a refusal has nobody to talk to: the
// check at save time is where an administrator hears about it.
func SanitizeCSS(css string) string {
	clean, err := CheckCSS(css)
	if err != nil {
		return ""
	}
	return clean
}

// --- images ------------------------------------------------------------------

// Image types we accept, by their magic bytes rather than by what the upload
// claims to be.
const (
	TypePNG  = "image/png"
	TypeWebP = "image/webp"
	TypeSVG  = "image/svg+xml"
	TypeICO  = "image/x-icon"
	TypeJPEG = "image/jpeg"
)

// DetectImage identifies an upload from its contents.
func DetectImage(data []byte) (string, error) {
	switch {
	case len(data) == 0:
		return "", ErrAssetInvalid
	case len(data) >= 8 && string(data[1:4]) == "PNG":
		return TypePNG, nil
	case len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return TypeWebP, nil
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF:
		return TypeJPEG, nil
	case len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00:
		return TypeICO, nil
	case looksLikeSVG(data):
		return TypeSVG, nil
	default:
		return "", ErrAssetType
	}
}

func looksLikeSVG(data []byte) bool {
	head := strings.ToLower(strings.TrimSpace(string(data[:min(len(data), 1024)])))
	return strings.HasPrefix(head, "<?xml") && strings.Contains(head, "<svg") ||
		strings.HasPrefix(head, "<svg") ||
		strings.HasPrefix(head, "<!doctype svg")
}

var (
	svgScriptPattern  = regexp.MustCompile(`(?is)<\s*(script|foreignobject|iframe|object|embed|audio|video|animate|set)\b`)
	svgHandlerPattern = regexp.MustCompile(`(?is)\son[a-z]+\s*=`)
	svgRemotePattern  = regexp.MustCompile(`(?is)(href|xlink:href|src)\s*=\s*["']?\s*(https?:|//|javascript:|data:text)`)
	svgEntityPattern  = regexp.MustCompile(`(?is)<!ENTITY`)
)

// CheckSVG refuses an SVG that could run script or fetch anything.
//
// An SVG is a document, not a picture: it can carry script, load remote
// resources and declare entities that expand into a denial of service. Peek
// serves it from its own origin, so anything inside it runs with the
// instance's authority — hence a refusal rather than a best-effort strip.
func CheckSVG(data []byte) error {
	if svgScriptPattern.Match(data) {
		return errors.New("this SVG contains script or embedded content; export it as a flat image first")
	}
	if svgHandlerPattern.Match(data) {
		return errors.New("this SVG contains event handlers; export it as a flat image first")
	}
	if svgRemotePattern.Match(data) {
		return errors.New("this SVG loads something from outside the instance")
	}
	if svgEntityPattern.Match(data) {
		return errors.New("this SVG declares XML entities, which Peek does not serve")
	}
	return nil
}

// ValidateAsset checks one upload and returns the content type to store.
func ValidateAsset(kind string, data []byte) (string, error) {
	if len(data) > MaxAssetBytes {
		return "", ErrAssetTooLarge
	}
	contentType, err := DetectImage(data)
	if err != nil {
		return "", err
	}
	if contentType == TypeSVG {
		if err := CheckSVG(data); err != nil {
			return "", err
		}
	}
	// A favicon that browsers will not read is worse than none at all.
	if kind == "favicon" && contentType == TypeJPEG {
		return "", errors.New("a favicon should be a PNG, an SVG or an ICO file")
	}
	return contentType, nil
}

// AssetETag fingerprints the bytes, for the cache-busting part of the URL.
func AssetETag(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(sum[:9])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
