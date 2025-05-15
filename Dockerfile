FROM rust:latest as builder

# Create a new empty shell project
WORKDIR /usr/src/app
COPY . .

# Build the application with release optimization
RUN cargo build --release

# Create a new stage with a minimal image
FROM debian:bookworm-slim

# Install any runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/discv5 /usr/local/bin/discv5

# Set the binary as the entrypoint
ENTRYPOINT ["discv5"]
