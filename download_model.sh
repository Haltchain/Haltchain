#!/bin/bash
# Download ONNX embedding model for semantic understanding
# This replaces the weak hash-projection with real transformer embeddings

set -e

MODEL_DIR="${HOME}/.cache/haltchain/models"
mkdir -p "$MODEL_DIR"

echo "Downloading all-MiniLM-L6-v2 ONNX model (~22MB)..."
echo "Target: $MODEL_DIR"

# Download model.onnx
if [ ! -f "$MODEL_DIR/model.onnx" ]; then
    echo "Downloading model.onnx..."
    curl -L -o "$MODEL_DIR/model.onnx" \
        "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx"
    echo "✓ model.onnx downloaded"
else
    echo "✓ model.onnx already exists"
fi

# Download tokenizer.json
if [ ! -f "$MODEL_DIR/tokenizer.json" ]; then
    echo "Downloading tokenizer.json..."
    curl -L -o "$MODEL_DIR/tokenizer.json" \
        "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/tokenizer.json"
    echo "✓ tokenizer.json downloaded"
else
    echo "✓ tokenizer.json already exists"
fi

echo ""
echo "Model download complete!"
echo "Location: $MODEL_DIR"
echo ""
echo "Run tests with:"
echo "  cargo test -p haltchain-cognitive --test prompt_injection"
