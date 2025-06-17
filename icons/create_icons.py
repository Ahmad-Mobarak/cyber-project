#!/usr/bin/python3

import os
import sys
from PIL import Image, ImageDraw
import math

def create_icon(name, size=64, draw_func=None, output_dir='icons'):
    """Create an icon with a given name and drawing function"""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    if draw_func:
        draw_func(draw, size)
    
    # Ensure the directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Save the image
    output_path = os.path.join(output_dir, f"{name}.png")
    img.save(output_path)
    print(f"Created icon: {output_path}")

def draw_file_icon(draw, size):
    """Draw a file icon"""
    # File colors
    primary_color = (25, 118, 210)  # Blue
    
    # Draw file shape
    margin = size // 8
    width = size - 2 * margin
    height = width * 1.2
    
    # Draw the main file shape
    draw.rectangle(
        [(margin, margin), (margin + width, margin + height)],
        fill=primary_color,
        outline=(255, 255, 255, 200),
        width=size//32
    )
    
    # Add folded corner
    corner_size = width // 4
    draw.polygon(
        [
            (margin + width - corner_size, margin),
            (margin + width, margin + corner_size),
            (margin + width, margin),
        ],
        fill=(255, 255, 255, 100)
    )
    
    # Add lines representing text
    line_width = width * 0.6
    line_height = height // 10
    line_margin = width // 5
    y_start = margin + height // 3
    
    for i in range(3):
        y = y_start + i * (line_height * 1.5)
        draw.rectangle(
            [(margin + line_margin, y), (margin + line_margin + line_width, y + line_height)],
            fill=(255, 255, 255, 150)
        )

def draw_folder_icon(draw, size):
    """Draw a folder icon"""
    # Folder colors
    folder_color = (255, 193, 7)  # Amber
    
    # Draw folder shape
    margin = size // 8
    width = size - 2 * margin
    height = width * 0.8
    
    # Draw the tab part
    tab_width = width // 3
    tab_height = height // 4
    draw.rectangle(
        [(margin, margin), (margin + tab_width, margin + tab_height)],
        fill=folder_color,
        outline=(255, 255, 255, 200),
        width=size//32
    )
    
    # Draw the main folder
    draw.rectangle(
        [(margin, margin + tab_height), (margin + width, margin + tab_height + height)],
        fill=folder_color,
        outline=(255, 255, 255, 200),
        width=size//32
    )

def draw_console_icon(draw, size):
    """Draw a console/terminal icon"""
    # Console colors
    console_color = (33, 33, 33)  # Dark Gray
    text_color = (0, 230, 118)    # Green
    
    # Draw console background
    margin = size // 8
    width = size - 2 * margin
    height = width * 0.8
    
    # Draw the console rectangle
    draw.rectangle(
        [(margin, margin), (margin + width, margin + height)],
        fill=console_color,
        outline=(255, 255, 255, 200),
        width=size//32
    )
    
    # Draw command prompt symbol
    prompt_margin = width // 5
    prompt_size = width // 3
    x1 = margin + prompt_margin
    y1 = margin + height // 2
    
    # Draw >
    draw.polygon(
        [
            (x1, y1),
            (x1 + prompt_size//2, y1 + prompt_size//2),
            (x1, y1 + prompt_size),
        ],
        fill=text_color
    )
    
    # Draw cursor/underscore
    cursor_width = prompt_size
    cursor_height = prompt_size // 5
    x2 = x1 + prompt_size * 0.7
    y2 = y1 + prompt_size // 2
    
    draw.rectangle(
        [(x2, y2), (x2 + cursor_width, y2 + cursor_height)],
        fill=text_color
    )

def draw_update_icon(draw, size):
    """Draw an update/refresh icon"""
    # Update colors
    update_color = (0, 200, 83)  # Green
    
    # Draw circular arrow
    margin = size // 8
    center = size // 2
    radius = size // 2 - margin
    
    # Draw circle segments for the refresh icon
    start_angle = 45
    end_angle = 315
    
    for angle in range(start_angle, end_angle, 1):
        rad = math.radians(angle)
        x1 = center + radius * math.cos(rad)
        y1 = center + radius * math.sin(rad)
        
        rad2 = math.radians(angle + 1)
        x2 = center + radius * math.cos(rad2)
        y2 = center + radius * math.sin(rad2)
        
        draw.line([(x1, y1), (x2, y2)], fill=update_color, width=size//10)
    
    # Draw arrow head
    arrow_size = size // 5
    arrow_angle = math.radians(start_angle)
    arrow_x = center + radius * math.cos(arrow_angle)
    arrow_y = center + radius * math.sin(arrow_angle)
    
    draw.polygon(
        [
            (arrow_x, arrow_y),
            (arrow_x - arrow_size, arrow_y - arrow_size//2),
            (arrow_x - arrow_size//2, arrow_y - arrow_size),
        ],
        fill=update_color
    )

def draw_check_icon(draw, size):
    """Draw a checkmark icon"""
    # Check colors
    check_color = (0, 200, 83)  # Green
    
    # Draw checkmark
    margin = size // 5
    
    # Draw the checkmark
    draw.line(
        [
            (margin, size//2),
            (size//2.5, size - margin),
            (size - margin, margin//2)
        ],
        fill=check_color,
        width=size//8
    )

def draw_clean_icon(draw, size):
    """Draw a cleaning/broom icon"""
    # Clean colors
    clean_color = (156, 39, 176)  # Purple
    
    # Draw broom
    margin = size // 8
    handle_width = size // 16
    
    # Draw handle
    draw.line(
        [(size//4, margin), (size * 3//4, size - margin)],
        fill=clean_color,
        width=handle_width
    )
    
    # Draw bristles
    bristle_length = size // 3
    bristle_width = size // 32
    
    for i in range(5):
        offset = i * (size//10)
        x1 = size//4 + offset
        y1 = margin + offset
        
        draw.line(
            [(x1, y1), (x1 - bristle_length//2, y1 + bristle_length)],
            fill=clean_color,
            width=bristle_width
        )

def draw_static_icon(draw, size):
    """Draw a static analysis icon"""
    # Static analysis colors
    static_color = (3, 169, 244)  # Light Blue
    
    # Draw document with magnifying glass
    margin = size // 8
    doc_width = size - 2 * margin
    doc_height = doc_width * 1.2
    
    # Draw document
    draw.rectangle(
        [(margin, margin), (margin + doc_width, margin + doc_height)],
        fill=(255, 255, 255, 100),
        outline=static_color,
        width=size//32
    )
    
    # Draw magnifying glass
    glass_center = (size * 2//3, size * 2//3)
    glass_radius = size // 6
    handle_length = size // 4
    handle_width = size // 16
    
    # Draw glass circle
    draw.ellipse(
        [
            (glass_center[0] - glass_radius, glass_center[1] - glass_radius),
            (glass_center[0] + glass_radius, glass_center[1] + glass_radius)
        ],
        outline=static_color,
        width=handle_width//2
    )
    
    # Draw handle
    angle = 45
    angle_rad = math.radians(angle)
    start_x = glass_center[0] + glass_radius * math.cos(angle_rad)
    start_y = glass_center[1] + glass_radius * math.sin(angle_rad)
    end_x = start_x + handle_length * math.cos(angle_rad)
    end_y = start_y + handle_length * math.sin(angle_rad)
    
    draw.line([(start_x, start_y), (end_x, end_y)], fill=static_color, width=handle_width)

def draw_dynamic_icon(draw, size):
    """Draw a dynamic analysis icon"""
    # Dynamic analysis colors
    dynamic_color = (233, 30, 99)  # Pink
    
    # Draw play button in a circle
    margin = size // 8
    center = size // 2
    radius = size // 2 - margin
    
    # Draw circle
    draw.ellipse(
        [(center - radius, center - radius), (center + radius, center + radius)],
        outline=dynamic_color,
        width=size//16
    )
    
    # Draw play triangle
    triangle_size = radius * 0.7
    
    draw.polygon(
        [
            (center - triangle_size//3, center - triangle_size//2),
            (center + triangle_size//1.5, center),
            (center - triangle_size//3, center + triangle_size//2),
        ],
        fill=dynamic_color
    )

def draw_document_icon(draw, size):
    """Draw a document analysis icon"""
    # Document colors
    document_color = (255, 152, 0)  # Orange
    
    # Draw document with lines
    margin = size // 8
    doc_width = size - 2 * margin
    doc_height = doc_width * 1.2
    
    # Draw document
    draw.rectangle(
        [(margin, margin), (margin + doc_width, margin + doc_height)],
        fill=(255, 255, 255, 100),
        outline=document_color,
        width=size//32
    )
    
    # Add folded corner
    corner_size = doc_width // 4
    draw.polygon(
        [
            (margin + doc_width - corner_size, margin),
            (margin + doc_width, margin + corner_size),
            (margin + doc_width, margin),
        ],
        fill=(255, 255, 255, 150)
    )
    
    # Add lines representing text
    line_width = doc_width * 0.7
    line_height = doc_height // 12
    line_margin = doc_width // 6
    
    for i in range(6):
        y = margin + doc_height // 5 + i * (line_height * 1.5)
        draw.rectangle(
            [(margin + line_margin, y), (margin + line_margin + line_width, y + line_height)],
            fill=document_color
        )

def draw_tools_icon(draw, size):
    """Draw a tools/utilities icon"""
    # Tools colors
    tools_color = (63, 81, 181)  # Indigo
    
    # Draw wrench
    margin = size // 6
    head_size = size // 3
    handle_width = size // 10
    handle_length = size - head_size - 2 * margin
    
    # Draw handle
    draw.rectangle(
        [
            (size//2 - handle_width//2, margin + head_size),
            (size//2 + handle_width//2, margin + head_size + handle_length)
        ],
        fill=tools_color
    )
    
    # Draw head (hexagon)
    center_x = size // 2
    center_y = margin + head_size // 2
    
    points = []
    for i in range(6):
        angle = i * 60
        angle_rad = math.radians(angle)
        x = center_x + head_size//2 * math.cos(angle_rad)
        y = center_y + head_size//2 * math.sin(angle_rad)
        points.append((x, y))
    
    draw.polygon(points, fill=tools_color)
    
    # Add highlight to make it look shiny
    draw.ellipse(
        [
            (center_x - head_size//4, center_y - head_size//4),
            (center_x + head_size//4, center_y + head_size//4)
        ],
        fill=(255, 255, 255, 100)
    )

def main():
    # Create all icons
    create_icon('file', draw_func=draw_file_icon)
    create_icon('folder', draw_func=draw_folder_icon)
    create_icon('console', draw_func=draw_console_icon)
    create_icon('update', draw_func=draw_update_icon)
    create_icon('check', draw_func=draw_check_icon)
    create_icon('clean', draw_func=draw_clean_icon)
    create_icon('static', draw_func=draw_static_icon)
    create_icon('dynamic', draw_func=draw_dynamic_icon)
    create_icon('document', draw_func=draw_document_icon)
    create_icon('tools', draw_func=draw_tools_icon)
    
    # Import and run the logo creator too
    from logo import create_logo
    create_logo()
    
    print("All icons created successfully!")

if __name__ == "__main__":
    main() 