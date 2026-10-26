package tool

import "testing"

func TestDiffIncludesSharedEdges(t *testing.T) {
	shared := Dep("shared", "1")
	a := Dep("", "", Dep("a", "1", shared), Dep("b", "1", shared))
	b := Dep("", "", Dep("a", "1", Dep("shared", "1")), Dep("b", "1"))
	if !Diff(a, b) {
		t.Fatal("missing shared edge was ignored")
	}
	c := Dep("", "", Dep("", "", Dep("b", "1", Dep("shared", "1")), Dep("a", "1", Dep("shared", "1"))))
	if Diff(a, c) {
		t.Fatal("container or traversal order changed graph identity")
	}
	if Diff(Dep("pkg", "1"), Dep("pkg", "2")) == false {
		t.Fatal("version difference ignored")
	}
}
