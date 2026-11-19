"""Mezclas de vistas compartidas por toda la interfaz."""

from django.core.paginator import EmptyPage, InvalidPage, PageNotAnInteger

PAGE_SIZES = (25, 50, 100)


class PaginationMixin:
    """Paginación tolerante y con tamaño de página elegible (``?per_page=25|50|100``).

    Una página fuera de rango (``?page=999`` tras filtrar) devuelve la última en lugar de un 404
    desnudo; una página no numérica, la primera.
    """

    paginate_by = 25

    def get_paginate_by(self, queryset):
        raw = self.request.GET.get("per_page")
        if raw and raw.isdigit() and int(raw) in PAGE_SIZES:
            return int(raw)
        return self.paginate_by

    def paginate_queryset(self, queryset, page_size):
        paginator = self.get_paginator(
            queryset,
            page_size,
            orphans=self.get_paginate_orphans(),
            allow_empty_first_page=self.get_allow_empty(),
        )
        page_kwarg = self.page_kwarg
        raw = self.kwargs.get(page_kwarg) or self.request.GET.get(page_kwarg) or 1
        try:
            number = paginator.validate_number(raw)
        except PageNotAnInteger:
            number = 1
        except EmptyPage:
            number = paginator.num_pages
        except InvalidPage:
            number = 1
        page = paginator.page(number)
        return paginator, page, page.object_list, page.has_other_pages()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["page_sizes"] = PAGE_SIZES
        ctx["per_page"] = self.get_paginate_by(None)
        return ctx
