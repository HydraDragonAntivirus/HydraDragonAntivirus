# Reconstructed from integrated Nuitka blob
# Module: uimgui.integrations.glumpy

a__qualname__

#version 330
uniform mat4 ProjMtx;
in vec2 Position;
in vec2 UV;
in vec4 Color;
out vec2 Frag_UV;
out vec4 Frag_Color;
void main() {
Frag_UV = UV;
Frag_Color = Color;
gl_Position = ProjMtx * vec4(Position.xy, 0, 1);
}

#version 330
uniform sampler2D Texture;
in vec2 Frag_UV;
in vec4 Frag_Color;
out vec4 Out_Color;
void main() {
vec4 col = Frag_Color; //original
Out_Color = col * texture(Texture, Frag_UV.st); //original
}
T tuGlumpyRenderer.__init__
a_get_clipboard_text
uGlumpyRenderer._get_clipboard_text
a_set_clipboard_text
uGlumpyRenderer._set_clipboard_text
uGlumpyRenderer._map_keys
uGlumpyRenderer.keyboard_callback
uGlumpyRenderer.char_callback
uGlumpyRenderer.resize_callback
uGlumpyRenderer.mouse_callback
uGlumpyRenderer.scroll_callback
process_inputs
uGlumpyRenderer.process_inputs
a_create_device_objects
uGlumpyRenderer._create_device_objects
refresh_font_texture
uGlumpyRenderer.refresh_font_texture
render
uGlumpyRenderer.render
a_invalidate_device_objects
uGlumpyRenderer._invalidate_device_objects
a__orig_bases__
uimgui\integrations\glumpy.py
u<module imgui.integrations.glumpy>
T a__class__
prog
T aself
window
attach_callbacks
a__class__
T aself
dtype
v_array
unitmat
T aself
T aself
key_map
T aself
text
T aself
window
char
io
T aself
window
key
scancode
action
mods
io
T aself
args
kwargs
T aself
io
window_size
fb_size
current_time
T aself
width
height
pixels
tex
T*aself
draw_data
io
display_width
display_height
fb_width
fb_height
last_program
last_texture
last_active_texture
last_array_buffer
last_element_array_buffer
last_vertex_array
last_blend_src
last_blend_dst
last_blend_equation_rgb
last_blend_equation_alpha
last_viewport
last_scissor_box
last_enable_blend
last_enable_cull_face
last_enable_depth_test
last_enable_scissor_test
ortho_projection
commands
idx_buffer_offset
array_type
data_carray
dtype
vao_content
dtype2
vao_content_f
wiaval
v_array
idx_content
command
wxwywzwwaidx_array
T aself
window
width
height
T aself
window
x_offset
y_offset

.imgui.integrations.opengl
a_shader_handle
a_vert_handle
a_fragment_handle
a_attrib_location_tex
a_attrib_proj_mtx
a_attrib_location_position
a_attrib_location_uv
a_attrib_location_color
a_vbo_handle
a_elements_handle
a_vao_handle
aProgrammablePipelineRenderer
a__init__
gl
glGetIntegerv
aGL_TEXTURE_BINDING_2D
io
fonts
get_tex_data_as_rgba32
utoo many values to unpack (expected 3)
a_font_texture
glDeleteTextures
glGenTextures
T l aglBindTexture
aGL_TEXTURE_2D
glTexParameteri
aGL_TEXTURE_MIN_FILTER
aGL_LINEAR
aGL_TEXTURE_MAG_FILTER
glTexImage2D
l
aGL_RGBA
aGL_UNSIGNED_BYTE
texture_id
clear_tex_data
aGL_ARRAY_BUFFER_BINDING
aGL_VERTEX_ARRAY_BINDING
glCreateProgram
glCreateShader
aGL_VERTEX_SHADER
aGL_FRAGMENT_SHADER
glShaderSource
aVERTEX_SHADER_SRC
aFRAGMENT_SHADER_SRC
glCompileShader
glAttachShader
glLinkProgram
glDeleteShader
glGetUniformLocation
aTexture
aProjMtx
glGetAttribLocation
aPosition
aUV
aColor
glGenBuffers
glGenVertexArrays
glBindVertexArray
glBindBuffer
aGL_ARRAY_BUFFER
glEnableVertexAttribArray
glVertexAttribPointer
l aGL_FLOAT
aGL_FALSE
imgui
aVERTEX_SIZE
c_void_p
aVERTEX_BUFFER_POS_OFFSET
aVERTEX_BUFFER_UV_OFFSET
l aGL_TRUE
aVERTEX_BUFFER_COL_OFFSET
display_size
utoo many values to unpack (expected 2)
display_fb_scale
l ascale_clip_rects
get_common_gl_state
aGL_CURRENT_PROGRAM
aGL_ACTIVE_TEXTURE
aGL_ELEMENT_ARRAY_BUFFER_BINDING
glEnable
aGL_BLEND
glBlendEquation
aGL_FUNC_ADD
glBlendFunc
aGL_SRC_ALPHA
aGL_ONE_MINUS_SRC_ALPHA
glDisable
aGL_CULL_FACE
aGL_DEPTH_TEST
aGL_SCISSOR_TEST
glActiveTexture
aGL_TEXTURE0
glPolygonMode
aGL_FRONT_AND_BACK
aGL_FILL
glViewport
c_float
l f
@Z
f
f
?aglUseProgram
glUniform1i
glUniformMatrix4fv
commands_lists
self
glBufferData
vtx_buffer_size
vtx_buffer_data
aGL_STREAM_DRAW
aGL_ELEMENT_ARRAY_BUFFER
idx_buffer_size
aINDEX_SIZE
idx_buffer_data
commands
clip_rect
utoo many values to unpack (expected 4)
glScissor
fb_height
aGL_UNSIGNED_SHORT
aGL_UNSIGNED_INT
glDrawElements
aGL_TRIANGLES
elem_count
idx_buffer_offset
restore_common_gl_state
q aglDeleteVertexArrays
glDeleteBuffers
glDeleteProgram
get_tex_data_as_alpha8
aGL_ALPHA
glPushAttrib
aGL_ENABLE_BIT
aGL_COLOR_BUFFER_BIT
aGL_TRANSFORM_BIT
glEnableClientState
aGL_VERTEX_ARRAY
aGL_TEXTURE_COORD_ARRAY
aGL_COLOR_ARRAY
glMatrixMode
aGL_PROJECTION
glPushMatrix
glLoadIdentity
glOrtho
wxwyaGL_MODELVIEW
glVertexPointer
glTexCoordPointer
glColorPointer
idx_buffer
glDisableClientState
glPopMatrix
glPopAttrib
aGL_VIEWPORT
glIsEnabled
aGL_SCISSOR_BOX
aGL_BLEND_SRC
aGL_BLEND_DST
aGL_BLEND_EQUATION_RGB
aGL_BLEND_EQUATION_ALPHA
aGL_POLYGON_MODE
utoo many values to unpack (expected 12)
glBlendEquationSeparate
l a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
absolute_import
uOpenGL.GL
aGL
ctypes
base
T aBaseOpenGLRenderer
aBaseOpenGLRenderer
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
