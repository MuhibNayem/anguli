package image

// ZhangSuenThinning reduces a binary matrix (1 = ridge, 0 = valley) to a 1-pixel wide skeleton.
// It rigorously implements the parallel iterative thinning algorithm without breaking topology.
func ZhangSuenThinning(binary [][]uint8, width, height int) [][]uint8 {
	skeleton := make([][]uint8, height)
	for y := 0; y < height; y++ {
		skeleton[y] = make([]uint8, width)
		copy(skeleton[y], binary[y])
	}

	type point struct{ x, y int }
	toDelete := make([]point, 0, 1024)

	changed := true
	for changed {
		changed = false

		// Sub-iteration 1
		toDelete = toDelete[:0]
		for y := 1; y < height-1; y++ {
			for x := 1; x < width-1; x++ {
				if skeleton[y][x] != 1 {
					continue
				}

				p2 := skeleton[y-1][x]
				p3 := skeleton[y-1][x+1]
				p4 := skeleton[y][x+1]
				p5 := skeleton[y+1][x+1]
				p6 := skeleton[y+1][x]
				p7 := skeleton[y+1][x-1]
				p8 := skeleton[y][x-1]
				p9 := skeleton[y-1][x-1]

				// Condition 1: 2 <= B(P1) <= 6
				b := p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9
				if b < 2 || b > 6 {
					continue
				}

				// Condition 2: A(P1) = 1 (number of 0->1 transitions in clock order)
				neighbors := [9]uint8{p2, p3, p4, p5, p6, p7, p8, p9, p2}
				a := 0
				for i := 0; i < 8; i++ {
					if neighbors[i] == 0 && neighbors[i+1] == 1 {
						a++
					}
				}
				if a != 1 {
					continue
				}

				// Condition 3: P2 * P4 * P6 == 0
				if p2*p4*p6 != 0 {
					continue
				}

				// Condition 4: P4 * P6 * P8 == 0
				if p4*p6*p8 != 0 {
					continue
				}

				toDelete = append(toDelete, point{x, y})
			}
		}

		if len(toDelete) > 0 {
			changed = true
			for _, pt := range toDelete {
				skeleton[pt.y][pt.x] = 0
			}
		}

		// Sub-iteration 2
		toDelete = toDelete[:0]
		for y := 1; y < height-1; y++ {
			for x := 1; x < width-1; x++ {
				if skeleton[y][x] != 1 {
					continue
				}

				p2 := skeleton[y-1][x]
				p3 := skeleton[y-1][x+1]
				p4 := skeleton[y][x+1]
				p5 := skeleton[y+1][x+1]
				p6 := skeleton[y+1][x]
				p7 := skeleton[y+1][x-1]
				p8 := skeleton[y][x-1]
				p9 := skeleton[y-1][x-1]

				b := p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9
				if b < 2 || b > 6 {
					continue
				}

				neighbors := [9]uint8{p2, p3, p4, p5, p6, p7, p8, p9, p2}
				a := 0
				for i := 0; i < 8; i++ {
					if neighbors[i] == 0 && neighbors[i+1] == 1 {
						a++
					}
				}
				if a != 1 {
					continue
				}

				// Condition 3: P2 * P4 * P8 == 0
				if p2*p4*p8 != 0 {
					continue
				}

				// Condition 4: P2 * P6 * P8 == 0
				if p2*p6*p8 != 0 {
					continue
				}

				toDelete = append(toDelete, point{x, y})
			}
		}

		if len(toDelete) > 0 {
			changed = true
			for _, pt := range toDelete {
				skeleton[pt.y][pt.x] = 0
			}
		}
	}

	return skeleton
}
