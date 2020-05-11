#version 330 core

layout (location = 0) in vec3 pos;
layout (location = 1) in vec2 in_tex_coord;

out vec2 out_tex_coord;

void main() {
	vec3 new_pos = pos * 0.8;
	gl_Position = vec4(new_pos, 1.0);
	out_tex_coord = in_tex_coord;
}
