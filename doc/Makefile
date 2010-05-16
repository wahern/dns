

all: dns.pdf # spf.pdf

%.pdf: %.tex
	@echo Pass 1
	@pdflatex $< >/dev/null </dev/null
	@echo Index
	@T="$<"; makeindex $${T%.tex}
	@echo Pass 2
	@pdflatex $< >/dev/null </dev/null
	@test -t 2 && open $@

clean:
	rm -f *.aux *.log *.pdf *.ilg *.idx *.ind *.toc *.out
