#!/usr/bin/python3

import os
import sys
from PIL import Image, ImageDraw, ImageFont
import math

def create_logo(size=128, output_path='icons/logo.png'):
    """
    Create a simple logo for the Qu1cksc0pe application
    """
    # Create a new image with a transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Define colors
    primary_color = (25, 118, 210)     # Blue
    secondary_color = (255, 87, 34)    # Orange
    
    # Draw background circle
    circle_center = (size//2, size//2)
    circle_radius = size//2 - 4
    
    # Draw main circle
    draw.ellipse(
        [(circle_center[0] - circle_radius, circle_center[1] - circle_radius),
         (circle_center[0] + circle_radius, circle_center[1] + circle_radius)],
        fill=primary_color
    )
    
    # Draw magnifying glass
    # Handle
    handle_width = size//10
    handle_length = size//2
    handle_angle = 45  # degrees
    
    # Convert angle to radians
    angle_rad = math.radians(handle_angle)
    
    # Starting point of handle (on the edge of the lens)
    lens_radius = size//3
    start_x = circle_center[0] + lens_radius * math.cos(angle_rad)
    start_y = circle_center[1] + lens_radius * math.sin(angle_rad)
    
    # End point of handle
    end_x = start_x + handle_length * math.cos(angle_rad)
    end_y = start_y + handle_length * math.sin(angle_rad)
    
    # Draw handle
    draw.line([(start_x, start_y), (end_x, end_y)], fill=secondary_color, width=handle_width)
    
    # Draw lens
    lens_center = circle_center
    draw.ellipse(
        [(lens_center[0] - lens_radius, lens_center[1] - lens_radius),
         (lens_center[0] + lens_radius, lens_center[1] + lens_radius)],
        outline=secondary_color,
        width=handle_width//2
    )
    
    # Draw inner circle for lens effect
    inner_radius = lens_radius - handle_width
    draw.ellipse(
        [(lens_center[0] - inner_radius, lens_center[1] - inner_radius),
         (lens_center[0] + inner_radius, lens_center[1] + inner_radius)],
        fill=(255, 255, 255, 100)  # Semi-transparent white
    )
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Save the image
    img.save(output_path)
    print(f"Logo created and saved to {output_path}")

if __name__ == "__main__":
    create_logo() 