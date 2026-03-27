# Étape de construction
FROM golang:1.22-alpine AS builder

# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers de dépendances
COPY go.mod go.sum ./
RUN go mod download

# Copier le code source et les ressources
COPY main.go ./
COPY admin.html ./

# Compiler l'application (le flag CGO_ENABLED=0 permet de compiler un binaire statique)
RUN CGO_ENABLED=0 GOOS=linux go build -o admin-panel .

# Étape d'exécution (image finale très légère)
FROM alpine:latest

WORKDIR /app

# Installer les certificats utiles (optionnel mais recommandé)
RUN apk --no-cache add ca-certificates tzdata

# Copier l'exécutable et le fichier HTML depuis l'étape de construction
COPY --from=builder /app/admin-panel .
COPY --from=builder /app/admin.html .

# Exposer le port 9000 (celui utilisé par l'application)
EXPOSE 9000

# Déclarer un point de montage pour la persistance de la base de données
VOLUME ["/app/data"]

# Commande pour démarrer l'application
CMD ["./admin-panel"]
