#version 330
in vec2 fragTexCoord;
out vec4 finalColor;
uniform sampler2D texture0;
uniform vec2 direction;

void main() {
    vec2 texSize = textureSize(texture0, 0);
    vec2 texel = 1.0 / texSize;
    
    vec4 color = vec4(0.0, 0.0, 0.0, 1);

    int width = 3;

    float weights[5] = float[5](0.0625, 0.25, 0.375, 0.25, 0.0625);

    for (int i = -width; i <= width; i++) {
        vec4 sample_color = texture(texture0, fragTexCoord + direction * i * texel)
            / (width * 2 + 1);
        color += sample_color;
    }

    finalColor = max(color, texture(texture0, fragTexCoord));
}
