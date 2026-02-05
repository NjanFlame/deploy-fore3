#!/bin/bash

# XeloraCloud Docker VPS Bot Setup Script
echo "🚀 Setting up XeloraCloud Docker VPS Bot..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo "❌ Docker daemon is not running. Please start Docker first."
    exit 1
fi

echo "✅ Docker is installed and running"

# Create necessary directories
echo "📁 Creating data directories..."
mkdir -p data logs

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your Discord bot token and admin ID"
    echo "   Then run: docker-compose up -d"
else
    echo "✅ .env file already exists"
fi

# Set proper permissions
echo "🔒 Setting permissions..."
chmod +x setup.sh
chmod 644 .env.example

# Test Docker functionality
echo "🔍 Testing Docker functionality..."
python3 tmp_rovodev_docker_test.py

# Build and start the bot
echo "🏗️  Building Docker image..."
docker-compose build

echo "🎉 Setup complete!"
echo ""
echo "To start the bot:"
echo "1. Edit .env file with your Discord token and admin ID"
echo "2. Run: docker-compose up -d"
echo ""
echo "To view logs:"
echo "docker-compose logs -f xeloracloud-bot"
echo ""
echo "To stop the bot:"
echo "docker-compose down"