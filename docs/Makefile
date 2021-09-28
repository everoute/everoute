# from https://github.com/kubernetes/website/blob/master/Makefile
DOCKER       = docker
HUGO_VERSION = 0.85.0
DOCKER_IMAGE = jojomi/hugo:$(HUGO_VERSION)
DOCKER_RUN   = $(DOCKER) run --rm --interactive --tty --volume $(realpath $(CURDIR)/..):/src -p 1313:1313 --workdir /src/docs --entrypoint=hugo $(DOCKER_IMAGE)

serve:
	$(DOCKER_RUN) server --bind="0.0.0.0" \
	--ignoreCache \
	--buildFuture \
	--disableFastRender
