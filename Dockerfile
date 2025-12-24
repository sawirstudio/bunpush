FROM gcr.io/distroless/base-debian12

WORKDIR /app

COPY bunpush /app/bunpush

EXPOSE 3000

USER nonroot:nonroot

CMD ["/app/bunpush"]