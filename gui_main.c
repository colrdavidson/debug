#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include "GL/gl.h"
#include "GL/glx.h"
#include "SDL2/SDL.h"

#define panic(...) do { dprintf(2, __VA_ARGS__); exit(1); } while (0)

#define GLFUNCS \
	GLE(void,   glGenBuffers,              GLsizei n, GLuint *buffers)                                                                       \
	GLE(void,   glGetShaderiv,             GLuint shader, GLenum pname, GLint *params)                                                       \
	GLE(void,   glGetShaderInfoLog,        GLuint shader, GLsizei max_length, GLsizei *length, GLchar *info_log)                             \
	GLE(GLuint, glCreateShader,            GLenum shaderType)                                                                                \
	GLE(void,   glShaderSource,            GLuint shader, GLsizei count, const GLchar **string, const GLint *length)                         \
	GLE(void,   glCompileShader,           GLuint shader)                                                                                    \
	GLE(GLuint, glCreateProgram,           void)                                                                                             \
	GLE(void,   glAttachShader,            GLuint program, GLuint shader)                                                                    \
	GLE(void,   glBindBuffer,              GLenum target, GLuint buffer)                                                                     \
	GLE(void,   glBufferData,              GLenum target, GLsizeiptr size, const GLvoid *data, GLenum usage)                                 \
	GLE(void,   glLinkProgram,             GLuint program)                                                                                   \
	GLE(void,   glUseProgram,              GLuint program)                                                                                   \
	GLE(GLint,  glGetAttribLocation,       GLuint program, const GLchar *name)                                                               \
	GLE(void,   glVertexAttribPointer,     GLuint idx, GLint size, GLenum type, GLboolean normalized, GLsizei stride, const GLvoid *pointer) \
	GLE(void,   glEnableVertexAttribArray, GLuint idx)                                                                                       \
	GLE(void,   glGenVertexArrays,         GLsizei n, GLuint *arrays)                                                                        \
	GLE(void,   glBindVertexArray,         GLuint array)                                                                                     \
	GLE(void,   glBindFragDataLocation,    GLuint program, GLuint color_number, const char *name)                                            \

#define GLE(ret, name, ...) typedef ret name##_func(__VA_ARGS__); name##_func *name;
GLFUNCS
#undef GLE

void init_gl_pointers(void) {
#define GLE(ret, name, ...) \
	name = (name##_func *)glXGetProcAddress((const GLubyte *)#name); \
	if (!name) {                                                     \
		panic("Function " #name " failed to load!\n");               \
	}                                                                \

	GLFUNCS
#undef GLE

}

char *file_to_str(char *name) {
	int fd = open(name, O_RDONLY);

	off_t f_end = lseek(fd, 0, SEEK_END);
	if (f_end < 0) {
		panic("Failed to seek to end of file!\n");
	}
	lseek(fd, 0, SEEK_SET);

	uint64_t size = (uint64_t)f_end;
	char *buffer = malloc(size + 1);

	ssize_t ret = read(fd, buffer, size);
	if (ret < 0 || (uint64_t)ret != size) {
		panic("Failed to read %s\n", name);
	}

	buffer[size] = '\0';
	close(fd);

	return buffer;
}

char *get_shader_err(GLuint shader) {
	int err_log_max_length = 0;
	glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &err_log_max_length);
	char *err_log = (char *)malloc(err_log_max_length);

	GLsizei err_log_length = 0;
	glGetShaderInfoLog(shader, err_log_max_length, &err_log_length, err_log);
	return err_log;
}

int build_shader(const char *file_str, GLenum shader_type) {
	uint32_t shader = glCreateShader(shader_type);
	glShaderSource(shader, 1, &file_str, NULL);

	glCompileShader(shader);

	int compile_success = 0;
	glGetShaderiv(shader, GL_COMPILE_STATUS, &compile_success);
	return shader;
}

uint32_t load_and_build_program(char *vert_name, char *frag_name) {
	uint32_t shader_program = glCreateProgram();

	char *vert_file = file_to_str(vert_name);
	char *frag_file = file_to_str(frag_name);

	int vert_shader = build_shader(vert_file, GL_VERTEX_SHADER);
	if (!vert_shader) {
		printf("Vert shader %d failed to compile!\n", vert_shader);
		panic("%s\n", get_shader_err(vert_shader));
	}

	int frag_shader = build_shader(frag_file, GL_FRAGMENT_SHADER);
	if (!frag_shader) {
		printf("Frag shader %d failed to compile!\n", frag_shader);
		panic("%s\n", get_shader_err(frag_shader));
	}

	free(vert_file);
	free(frag_file);

	glAttachShader(shader_program, vert_shader);
	glAttachShader(shader_program, frag_shader);

	return shader_program;
}

int main() {
	SDL_Init(SDL_INIT_VIDEO);

	int width  = 800;
	int height = 600;
	SDL_Window *window = SDL_CreateWindow("Debug", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, width, height, SDL_WINDOW_OPENGL | SDL_WINDOW_SHOWN);
	if (!window) {
		panic("Failed to get window! %s\n", SDL_GetError());
	}

	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 4);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 5);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
	SDL_GLContext gl_ctx = SDL_GL_CreateContext(window);
	if (!gl_ctx) {
		panic("Failed to create an OpenGL context\n");
	}

	SDL_GL_SetSwapInterval(1);
	SDL_GL_GetDrawableSize(window, &width, &height);
	printf("%d, %d\n", width, height);

	printf("GL version: %s\n", glGetString(GL_VERSION));
	init_gl_pointers();

	uint32_t vao;
	glGenVertexArrays(1, &vao);
	glBindVertexArray(vao);

	uint32_t vbo;
	glGenBuffers(1, &vbo);

	float verts[] = {
		0.0f,  0.5f,
		0.5f, -0.5f,
	   -0.5f, -0.5f
	};

	glBindBuffer(GL_ARRAY_BUFFER, vbo);
	glBufferData(GL_ARRAY_BUFFER, sizeof(verts), verts, GL_STATIC_DRAW);

	uint32_t program = load_and_build_program("vert.vsh", "frag.fsh");
	glBindFragDataLocation(program, 0, "out_color");
	glLinkProgram(program);
	glUseProgram(program);

	int pos_attrib = glGetAttribLocation(program, "pos");
	glEnableVertexAttribArray(pos_attrib);
	glVertexAttribPointer(pos_attrib, 2, GL_FLOAT, GL_FALSE, 0, 0);

	for (;;) {
		SDL_Event event;

		while (SDL_PollEvent(&event)) {
			switch (event.type) {
				case SDL_QUIT: {
					return 0;
				} break;
			}
		}

		glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
		glClear(GL_COLOR_BUFFER_BIT);

		glDrawArrays(GL_TRIANGLES, 0, 3);

		SDL_GL_SwapWindow(window);
	}

	return 0;
}
