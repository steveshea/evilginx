package core

func combineHost(sub, domain string) string {
	if sub == "" {
		return domain
	}
	return sub + "." + domain
}

func stringExists(s string, sa []string) bool {
	for _, k := range sa {
		if s == k {
			return true
		}
	}
	return false
}

func intExists(i int, ia []int) bool {
	for _, k := range ia {
		if i == k {
			return true
		}
	}
	return false
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		ml := maxLen
		pre := s[:ml/2-1]
		suf := s[len(s)-(ml/2-2):]
		return pre + "..." + suf
	}
	return s
}
