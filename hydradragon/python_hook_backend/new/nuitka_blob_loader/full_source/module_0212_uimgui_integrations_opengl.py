# Reconstructed from integrated Nuitka blob
# Module: uimgui.integrations.opengl

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
Out_Color = Frag_Color * texture(Texture, Frag_UV.st);
}
uProgrammablePipelineRenderer.__init__
refresh_font_texture
uProgrammablePipelineRenderer.refresh_font_texture
a_create_device_objects
uProgrammablePipelineRenderer._create_device_objects
render
uProgrammablePipelineRenderer.render
a_invalidate_device_objects
uProgrammablePipelineRenderer._invalidate_device_objects
a__orig_bases__
aFixedPipelineRenderer
uFixedPipelineRenderer.refresh_font_texture
uFixedPipelineRenderer._create_device_objects
uFixedPipelineRenderer.render
uFixedPipelineRenderer._invalidate_device_objects
uimgui\integrations\opengl.py
u<module imgui.integrations.opengl>
T a__class__
T aself
a__class__
T aself
T aself
last_texture
last_array_buffer
last_vertex_array
vertex_shader
fragment_shader
Talast_texture
last_viewport
last_enable_blend
last_enable_cull_face
last_enable_depth_test
last_enable_scissor_test
last_scissor_box
last_blend_src
last_blend_dst
last_blend_equation_rgb
last_blend_equation_alpha
last_front_and_back_polygon_mode
w_T aself
width
height
pixels
T aself
last_texture
width
height
pixels
T aself
draw_data
io
display_width
display_height
fb_width
fb_height
common_gl_state_tuple
commands
idx_buffer
command
wxwywzwwagltype
T aself
draw_data
io
display_width
display_height
fb_width
fb_height
common_gl_state_tuple
last_program
last_active_texture
last_array_buffer
last_element_array_buffer
last_vertex_array
ortho_projection
commands
idx_buffer_offset
command
wxwywzwwagltype
Tacommon_gl_state_tuple
last_texture
last_viewport
last_enable_blend
last_enable_cull_face
last_enable_depth_test
last_enable_scissor_test
last_scissor_box
last_blend_src
last_blend_dst
last_blend_equation_rgb
last_blend_equation_alpha
last_front_and_back_polygon_mode

.imgui.integrations.pygame
aPygameRenderer
a__init__
a_gui_time
custom_key_map
a_map_keys
io
key_map
a_custom_key
pygame
aK_TAB
imgui
aKEY_TAB
aK_LEFT
aKEY_LEFT_ARROW
aK_RIGHT
aKEY_RIGHT_ARROW
aK_UP
aKEY_UP_ARROW
aK_DOWN
aKEY_DOWN_ARROW
aK_PAGEUP
aKEY_PAGE_UP
aK_PAGEDOWN
aKEY_PAGE_DOWN
aK_HOME
aKEY_HOME
aK_END
aKEY_END
aK_INSERT
aKEY_INSERT
aK_DELETE
aKEY_DELETE
aK_BACKSPACE
aKEY_BACKSPACE
aK_SPACE
aKEY_SPACE
aK_RETURN
aKEY_ENTER
aK_ESCAPE
aKEY_ESCAPE
aK_KP_ENTER
aKEY_PAD_ENTER
aK_a
aKEY_A
aK_c
aKEY_C
aK_v
aKEY_V
aK_x
aKEY_X
aK_y
aKEY_Y
aK_z
aKEY_Z
type
aMOUSEMOTION
pos
mouse_pos
aMOUSEBUTTONDOWN
button
l amouse_down
l
l l aMOUSEBUTTONUP
l f
?amouse_wheel
l f
aKEYDOWN
unicode
l   aadd_input_character
keys_down
key
aKEYUP
aK_LCTRL
aK_RCTRL
key_ctrl
aK_LALT
aK_RALT
key_alt
aK_LSHIFT
aK_RSHIFT
key_shift
aK_LSUPER
key_super
aVIDEORESIZE
display
get_surface
set_mode
wwwhaget_flags
T aflags
refresh_font_texture
size
display_size
get_io
time
get_ticks
f
@ @adelta_time
f       ?Z
f    MbP?a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
absolute_import
opengl
T aFixedPipelineRenderer
aFixedPipelineRenderer
upygame.event
upygame.time
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
