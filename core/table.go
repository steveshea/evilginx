/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
)

func viewLen(s string) int {
	var ansi = regexp.MustCompile("\033\\[(?:[0-9]{1,3}(?:;[0-9]{1,3})*)?[m|K]") //nolint:gocritic // don't know what this does
	for _, m := range ansi.FindAllString(s, -1) {
		s = strings.ReplaceAll(s, m, "")
	}
	return utf8.RuneCountInString(s)
}

func truncString(s string, maxLen int) string {
	var ansi = regexp.MustCompile("\033\\[(?:[0-9]{1,3}(?:;[0-9]{1,3})*)?[m|K]") //nolint:gocritic // don't know what this does
	sm := s
	for _, m := range ansi.FindAllString(sm, -1) {
		sm = strings.ReplaceAll(sm, m, "")
	}
	nsm := sm
	if utf8.RuneCountInString(sm) > maxLen {
		if maxLen > 3 {
			nsm = nsm[:maxLen-3] + "..."
		} else {
			nsm = nsm[:maxLen]
		}
		s = strings.ReplaceAll(s, sm, nsm)
	}
	return s
}

func maxLen(strSlice []string) int {
	maxLen := 0
	for _, s := range strSlice {
		length := viewLen(s)
		if length > maxLen {
			maxLen = length
		}
	}
	return maxLen
}

type Alignment int

const (
	AlignLeft   = Alignment(0)
	AlignCenter = Alignment(1)
	AlignRight  = Alignment(2)
)

const minColLen = 16

func getPads(s string, maxLen int, align Alignment) (lPad, rPad int) {
	length := viewLen(s)
	diff := maxLen - length

	switch {
	case align == AlignLeft:
		lPad = 0
		rPad = diff - lPad + 1

	case align == AlignCenter:
		lPad = diff / 2
		rPad = diff - lPad + 1

	case align == AlignRight:
		lPad = diff + 1
		rPad = 0
	}

	return
}

func padded(s string, maxLen int, align Alignment) string {
	lPad, rPad := getPads(s, maxLen, align)
	return fmt.Sprintf("%s%s%s", strings.Repeat(" ", lPad), s, strings.Repeat(" ", rPad))
}

func AsTable(columns []string, rows [][]string) string {

	dg := color.New(color.FgHiBlack)
	for i, col := range columns {
		clen := viewLen(col) + 4
		if clen < minColLen {
			clen = minColLen
		}

		columns[i] = fmt.Sprintf(" %s ", col)
	}

	for i, row := range rows {
		for j, cell := range row {
			rows[i][j] = fmt.Sprintf(" %s ", cell) // cell
		}
	}

	colPaddings := make([]int, 0)
	lineSep := ""
	for colIndex, colHeader := range columns {
		column := []string{colHeader}
		for _, row := range rows {

			column = append(column, row[colIndex])
		}
		mLen := maxLen(column)
		colPaddings = append(colPaddings, mLen)
		lineSep += fmt.Sprintf("+%s", strings.Repeat("-", mLen+1))
	}
	lineSep += "+"

	table := ""

	// header
	table += dg.Sprintf("%s\n", lineSep)
	for colIndex, colHeader := range columns {
		table += dg.Sprintf("|") + padded(colHeader, colPaddings[colIndex], AlignCenter)
	}
	table += dg.Sprintf("|\n")
	table += dg.Sprintf("%s\n", lineSep)

	// rows
	for _, row := range rows {
		for colIndex, cell := range row {
			table += dg.Sprintf("|") + padded(cell, colPaddings[colIndex], AlignLeft)
		}
		table += dg.Sprintf("|\n")
	}

	// footer
	table += dg.Sprintf(lineSep) + "\n"

	return table
}

func AsRows(keys, vals []string) string {
	clr := color.New(color.FgHiBlack)
	mLen := maxLen(keys)
	var table string
	for i := range keys {
		table += clr.Sprintf(" %s : ", padded(keys[i], mLen, AlignLeft)) + fmt.Sprintf("%s\n", vals[i])
	}
	return table
}

func AsDescription(keys, vals []string) string {
	clr := color.New(color.FgHiBlack)
	var table string
	for i := range keys {
		table += clr.Sprintf(" %s", keys[i]) + fmt.Sprintf("\n   %s\n", vals[i])
	}
	return table
}
