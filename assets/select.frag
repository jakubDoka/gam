#version 330
in vec2 fragTexCoord;
out vec4 finalColor;
uniform sampler2D texture0;

void main() {
    vec2 texSize = textureSize(texture0, 0);
    vec2 texel = 1.0 / texSize;
    
    vec4 color = vec4(0.0);
    vec3 target = vec3(0x2B, 0xC6, 0xFF) / 255.0;
    vec4 sample_color = texture(texture0, fragTexCoord);

    if (distance(sample_color.rgb, target) < 0.2) {
        color += sample_color;
    }

    finalColor = color;
}
