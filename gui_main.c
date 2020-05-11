#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include "GL/gl.h"
#include "GL/glx.h"
#include "SDL2/SDL.h"

#define STB_TRUETYPE_IMPLEMENTATION
#include "stb_truetype.h"

#define panic(...) do { dprintf(2, __VA_ARGS__); exit(1); } while (0)
#define max(x, y) (((x) > (y)) ? (x) : (y))

#define GLFUNCS \
	GLE(void,      glGenBuffers,              GLsizei n, GLuint *buffers)                                                                       \
	GLE(void,      glGetShaderiv,             GLuint shader, GLenum pname, GLint *params)                                                       \
	GLE(void,      glGetShaderInfoLog,        GLuint shader, GLsizei max_length, GLsizei *length, GLchar *info_log)                             \
	GLE(GLuint,    glCreateShader,            GLenum shaderType)                                                                                \
	GLE(void,      glShaderSource,            GLuint shader, GLsizei count, const GLchar **string, const GLint *length)                         \
	GLE(void,      glCompileShader,           GLuint shader)                                                                                    \
	GLE(GLuint,    glCreateProgram,           void)                                                                                             \
	GLE(void,      glAttachShader,            GLuint program, GLuint shader)                                                                    \
	GLE(void *,    glMapBuffer,               GLenum target, GLenum access)                                                                     \
	GLE(GLboolean, glUnmapBuffer,             GLenum target)                                                                                    \
	GLE(void,      glBindBuffer,              GLenum target, GLuint buffer)                                                                     \
	GLE(void,      glBufferData,              GLenum target, GLsizeiptr size, const GLvoid *data, GLenum usage)                                 \
	GLE(void,      glLinkProgram,             GLuint program)                                                                                   \
	GLE(void,      glUseProgram,              GLuint program)                                                                                   \
	GLE(GLint,     glGetAttribLocation,       GLuint program, const GLchar *name)                                                               \
	GLE(GLint,     glGetUniformLocation,      GLuint program, const GLchar *name)                                                               \
	GLE(void,      glVertexAttribPointer,     GLuint idx, GLint size, GLenum type, GLboolean normalized, GLsizei stride, const GLvoid *pointer) \
	GLE(void,      glEnableVertexAttribArray, GLuint idx)                                                                                       \
	GLE(void,      glGenVertexArrays,         GLsizei n, GLuint *arrays)                                                                        \
	GLE(void,      glBindVertexArray,         GLuint array)                                                                                     \
	GLE(void,      glBindFragDataLocation,    GLuint program, GLuint color_number, const char *name)                                            \
	GLE(void,      glUniform1i,    		      GLint location, GLint v0)                                                                         \
	GLE(void,      glUniformMatrix4fv,    	  GLint location, GLsizei count, GLboolean transpose, const GLfloat *value)                         \
	GLE(void,      glGenerateMipmap,    	  GLenum target)                         															\

#define GLE(ret, name, ...) typedef ret name##_func(__VA_ARGS__); name##_func *name;
GLFUNCS
#undef GLE

#define MAX_VERT_MEMORY    512 * 1024
#define MAX_ELEMENT_MEMORY 128 * 1024

void init_gl_pointers(void) {
#define GLE(ret, name, ...) \
	name = (name##_func *)glXGetProcAddress((const GLubyte *)#name); \
	if (!name) {                                                     \
		panic("Function " #name " failed to load!\n");               \
	}                                                                \

	GLFUNCS
#undef GLE
}

typedef struct {
	float position[3];
	float tex_coord[2];
} vertex_t;

uint8_t *file_to_bin(char *name, int *file_size) {
	int fd = open(name, O_RDONLY);

	off_t f_end = lseek(fd, 0, SEEK_END);
	if (f_end < 0) {
		panic("Failed to seek to end of file!\n");
	}
	lseek(fd, 0, SEEK_SET);

	uint64_t size = (uint64_t)f_end;
	uint8_t *buffer = malloc(size);

	ssize_t ret = read(fd, buffer, size);
	if (ret < 0 || (uint64_t)ret != size) {
		panic("Failed to read %s\n", name);
	}

	close(fd);

	if (file_size) {
		*file_size = size;
	}

	return buffer;
}

char *file_to_str(char *name, int *file_size) {
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

	if (file_size) {
		*file_size = size;
	}

	return buffer;
}

char *get_shader_err(GLuint shader) {
	int err_log_max_length = 0;
	glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &err_log_max_length);
	if (!err_log_max_length) {
		panic("Failed to get log length!\n");
	}

	char *err_log = (char *)malloc(err_log_max_length);
	if (!err_log) {
		panic("Failed to malloc space for the error log!\n");
	}

	GLsizei err_log_length = 0;
	glGetShaderInfoLog(shader, err_log_max_length, &err_log_length, err_log);
	return err_log;
}

int build_shader(const char *file_str, GLenum shader_type, int *ret_shader) {
	uint32_t shader = glCreateShader(shader_type);
	glShaderSource(shader, 1, &file_str, NULL);
	glCompileShader(shader);
	*ret_shader = shader;

	int compile_success = 0;
	glGetShaderiv(shader, GL_COMPILE_STATUS, &compile_success);
	return compile_success;
}

uint32_t load_and_build_program(char *vert_name, char *frag_name) {
	uint32_t shader_program = glCreateProgram();

	char *vert_file = file_to_str(vert_name, NULL);
	char *frag_file = file_to_str(frag_name, NULL);

	int vert_shader, frag_shader, success;

	success = build_shader(vert_file, GL_VERTEX_SHADER, &vert_shader);
	if (!success) {
		printf("Vert shader %d failed to compile!\n", vert_shader);
		panic("%s\n", get_shader_err(vert_shader));
	}

	success = build_shader(frag_file, GL_FRAGMENT_SHADER, &frag_shader);
	if (!success) {
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
	int height = 800;
	SDL_Window *window = SDL_CreateWindow("Debug", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, width, height, SDL_WINDOW_OPENGL | SDL_WINDOW_SHOWN);
	if (!window) {
		panic("Failed to get window! %s\n", SDL_GetError());
	}

	SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 4);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 5);
	SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
	SDL_GLContext gl_ctx = SDL_GL_CreateContext(window);
	if (!gl_ctx) {
		panic("Failed to create an OpenGL context\n");
	}

	printf("GL version: %s\n", glGetString(GL_VERSION));
	init_gl_pointers();

	glViewport(0, 0, width, height);

	SDL_GL_SetSwapInterval(1);
	SDL_GL_GetDrawableSize(window, &width, &height);
	printf("%d, %d\n", width, height);

	int file_size;
	char *fileblob = file_to_str("main.c", &file_size);

	uint8_t *fontblob = file_to_bin("ProggyClean.ttf", &file_size);

	stbtt_fontinfo font;
	stbtt_InitFont(&font, fontblob, stbtt_GetFontOffsetForIndex((uint8_t *)fontblob, 0));

	int font_width, font_height;
	uint8_t *char_bits = stbtt_GetCodepointBitmap(&font, 0, stbtt_ScaleForPixelHeight(&font, height * 2), 'Q', &font_width, &font_height, 0, 0);

	uint32_t pre_sq_val = max(font_width, font_height);
	uint32_t nearest_sq = (1 << (32 - __builtin_clz(pre_sq_val - 1)));

	int bitmap_height = nearest_sq;
	int bitmap_width  = nearest_sq;

	uint8_t *bitmap = calloc(sizeof(uint32_t), bitmap_width * bitmap_height);

	uint8_t *src = char_bits;
	uint8_t *dest_row = bitmap + (sizeof(uint32_t) * bitmap_width * (bitmap_height - 1));
	for (int y = 0; y < font_height; y++) {

		uint32_t *dest = (uint32_t *)dest_row;
		for (int x = 0; x < font_width; x++) {
			uint8_t alpha = *src++;
			*dest++ = ((alpha << 24) | (alpha << 16) | (alpha << 8) | (alpha << 0));
		}

		dest_row -= bitmap_width * 4;
	}

	uint32_t program = load_and_build_program("vert.vsh", "frag.fsh");
	glLinkProgram(program);

	float verts[] = {
		 1.0f,  1.0f,  0.0f,   1.0f, 1.0f,
		 1.0f, -1.0f,  0.0f,   1.0f, 0.0f,
		-1.0f, -1.0f,  0.0f,   0.0f, 0.0f,
		-1.0f,  1.0f,  0.0f,   0.0f, 1.0f
	};

	uint32_t indices[] = {
		0, 1, 3,
		1, 2, 3
	};

	GLuint vao, vbo, ebo;
	glGenVertexArrays(1, &vao);
	glGenBuffers(1, &vbo);
	glGenBuffers(1, &ebo);

	glBindVertexArray(vao);

	glBindBuffer(GL_ARRAY_BUFFER, vbo);
	glBufferData(GL_ARRAY_BUFFER, sizeof(verts), verts, GL_STATIC_DRAW);

	glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, ebo);
	glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(indices), indices, GL_STATIC_DRAW);

	glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 5 * sizeof(float), (void *)0);
	glEnableVertexAttribArray(0);

	glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 5 * sizeof(float), (void *)(3 * sizeof(float)));
	glEnableVertexAttribArray(1);


	uint32_t tex;
	glGenTextures(1, &tex);
	glBindTexture(GL_TEXTURE_2D, tex);

	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);

	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, bitmap_width, bitmap_height, 0, GL_RGBA, GL_UNSIGNED_BYTE, bitmap);

	for (;;) {
		SDL_Event event;

		while (SDL_PollEvent(&event)) {
			switch (event.type) {
				case SDL_MOUSEBUTTONDOWN:
				case SDL_MOUSEBUTTONUP: {
					bool down = event.type == SDL_MOUSEBUTTONDOWN;
					int x = event.button.x;
					int y = event.button.y;

					if (event.button.button == SDL_BUTTON_LEFT) {
					}
				} break;
				case SDL_MOUSEWHEEL: {
				} break;
				case SDL_QUIT: {
					return 0;
				} break;
			}
		}

		glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
		glClear(GL_COLOR_BUFFER_BIT);

		int display_width, display_height;
		SDL_GL_GetDrawableSize(window, &display_width, &display_height);
		glViewport(0, 0, display_width, display_height);

		glActiveTexture(GL_TEXTURE0);
		glBindTexture(GL_TEXTURE_2D, tex);

		glUseProgram(program);
		glBindVertexArray(vao);

		glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, 0);

		SDL_GL_SwapWindow(window);
	}

	return 0;
}
