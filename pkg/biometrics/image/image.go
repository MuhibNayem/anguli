package image

import (
	"errors"
	"math"
)

var (
	ErrInvalidDimensions = errors.New("image dimensions must be strictly positive")
	ErrBufferMismatch    = errors.New("image buffer length does not match width * height")
)

// GrayImage represents an 8-bit grayscale image buffer.
type GrayImage struct {
	Width  int
	Height int
	Pix    []uint8
}

// NewGrayImage creates a new grayscale image.
func NewGrayImage(width, height int, pix []uint8) (*GrayImage, error) {
	if width <= 0 || height <= 0 {
		return nil, ErrInvalidDimensions
	}
	if len(pix) != width*height {
		return nil, ErrBufferMismatch
	}
	return &GrayImage{
		Width:  width,
		Height: height,
		Pix:    pix,
	}, nil
}

// At returns the pixel value at (x, y).
func (img *GrayImage) At(x, y int) uint8 {
	if x < 0 || x >= img.Width || y < 0 || y >= img.Height {
		return 0
	}
	return img.Pix[y*img.Width+x]
}

// Set sets the pixel value at (x, y).
func (img *GrayImage) Set(x, y int, val uint8) {
	if x >= 0 && x < img.Width && y >= 0 && y < img.Height {
		img.Pix[y*img.Width+x] = val
	}
}

// Normalize applies Hong-Wan-Jain global contrast standardization with target mean and variance.
func (img *GrayImage) Normalize(targetMean, targetVar float64) *GrayImage {
	out := &GrayImage{
		Width:  img.Width,
		Height: img.Height,
		Pix:    make([]uint8, len(img.Pix)),
	}

	if len(img.Pix) == 0 {
		return out
	}

	// Calculate image mean
	var sum float64
	for _, p := range img.Pix {
		sum += float64(p)
	}
	mean := sum / float64(len(img.Pix))

	// Calculate image variance
	var varSum float64
	for _, p := range img.Pix {
		diff := float64(p) - mean
		varSum += diff * diff
	}
	variance := varSum / float64(len(img.Pix))
	if variance < 1e-6 {
		variance = 1e-6
	}

	// M4: Directly scale pixel variance avoiding redundant sqrt calls in loop
	scale := math.Sqrt(targetVar / variance)

	for i, p := range img.Pix {
		val := float64(p)
		normVal := targetMean + (val-mean)*scale

		if normVal < 0 {
			normVal = 0
		} else if normVal > 255 {
			normVal = 255
		}
		out.Pix[i] = uint8(normVal)
	}

	return out
}

// OrientationField computes the local ridge orientation (in radians [0, π)) using Sobel gradient estimates.
func (img *GrayImage) OrientationField(blockSize int) [][]float64 {
	rows := (img.Height + blockSize - 1) / blockSize
	cols := (img.Width + blockSize - 1) / blockSize

	orientations := make([][]float64, rows)
	for r := 0; r < rows; r++ {
		orientations[r] = make([]float64, cols)
	}

	// Sobel operators with boundary-safe gradient sampling (M5)
	for r := 0; r < rows; r++ {
		for c := 0; c < cols; c++ {
			var gxx, gyy, gxy float64

			startY := r * blockSize
			endY := startY + blockSize
			if endY > img.Height {
				endY = img.Height
			}

			startX := c * blockSize
			endX := startX + blockSize
			if endX > img.Width {
				endX = img.Width
			}

			// Ensure bounds are strictly inside image boundaries [1, Width-2] and [1, Height-2]
			yMin := startY
			if yMin < 1 {
				yMin = 1
			}
			yMax := endY
			if yMax > img.Height-1 {
				yMax = img.Height - 1
			}

			xMin := startX
			if xMin < 1 {
				xMin = 1
			}
			xMax := endX
			if xMax > img.Width-1 {
				xMax = img.Width - 1
			}

			sampleCount := 0
			for y := yMin; y < yMax; y++ {
				for x := xMin; x < xMax; x++ {
					// Horizontal gradient Gx
					gx := float64(img.At(x+1, y-1)) + 2.0*float64(img.At(x+1, y)) + float64(img.At(x+1, y+1)) -
						(float64(img.At(x-1, y-1)) + 2.0*float64(img.At(x-1, y)) + float64(img.At(x-1, y+1)))

					// Vertical gradient Gy
					gy := float64(img.At(x-1, y+1)) + 2.0*float64(img.At(x, y+1)) + float64(img.At(x+1, y+1)) -
						(float64(img.At(x-1, y-1)) + 2.0*float64(img.At(x, y-1)) + float64(img.At(x+1, y-1)))

					gxx += gx * gx
					gyy += gy * gy
					gxy += gx * gy
					sampleCount++
				}
			}

			if sampleCount == 0 || (gxx+gyy) < 1e-6 {
				// If boundary block has no valid internal pixels or no contrast, borrow neighbor orientation
				if c > 0 {
					orientations[r][c] = orientations[r][c-1]
				} else if r > 0 {
					orientations[r][c] = orientations[r-1][c]
				} else {
					orientations[r][c] = 0.0
				}
				continue
			}

			denom := gxx - gyy
			numer := 2.0 * gxy
			theta := 0.5 * math.Atan2(numer, denom)
			// Rotate by 90 degrees to align with ridge flow (perpendicular to gradient)
			theta += math.Pi / 2.0
			for theta < 0 {
				theta += math.Pi
			}
			for theta >= math.Pi {
				theta -= math.Pi
			}

			orientations[r][c] = theta
		}
	}

	return orientations
}

// AdaptiveBinarize converts grayscale image into binary representation using an O(1) Integral Image (Summed-Area Table).
func (img *GrayImage) AdaptiveBinarize(windowSize int) [][]uint8 {
	binary := make([][]uint8, img.Height)
	for y := 0; y < img.Height; y++ {
		binary[y] = make([]uint8, img.Width)
	}

	// 1. Build Integral Image table in O(W * H)
	integral := make([][]int, img.Height+1)
	for y := 0; y <= img.Height; y++ {
		integral[y] = make([]int, img.Width+1)
	}

	for y := 0; y < img.Height; y++ {
		rowSum := 0
		for x := 0; x < img.Width; x++ {
			rowSum += int(img.At(x, y))
			integral[y+1][x+1] = integral[y][x+1] + rowSum
		}
	}

	// 2. Perform O(1) box sum per pixel
	half := windowSize / 2
	for y := 0; y < img.Height; y++ {
		y1 := y - half
		if y1 < 0 {
			y1 = 0
		}
		y2 := y + half
		if y2 >= img.Height {
			y2 = img.Height - 1
		}

		for x := 0; x < img.Width; x++ {
			x1 := x - half
			if x1 < 0 {
				x1 = 0
			}
			x2 := x + half
			if x2 >= img.Width {
				x2 = img.Width - 1
			}

			count := (x2 - x1 + 1) * (y2 - y1 + 1)
			sum := integral[y2+1][x2+1] - integral[y1][x2+1] - integral[y2+1][x1] + integral[y1][x1]

			// M6: Floating-point precision for local mean threshold
			localMean := float64(sum) / float64(count)
			if float64(img.At(x, y)) < localMean-2.0 {
				binary[y][x] = 1 // Ridge
			} else {
				binary[y][x] = 0 // Valley
			}
		}
	}

	return binary
}
