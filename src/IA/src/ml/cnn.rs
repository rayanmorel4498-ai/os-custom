// Convolutional Neural Networks - Real Image Processing

use ndarray::{Array4, Array3, Array2, s};
use std::sync::Arc;

/// Conv2D Layer
pub struct Conv2D {
    pub kernels: Array4<f64>, // [out_channels, in_channels, kernel_h, kernel_w]
    pub bias: Array2<f64>,    // [out_channels, out_h*out_w]
    pub padding: usize,
    pub stride: usize,
    pub out_channels: usize,
}

impl Conv2D {
    pub fn new(
        in_channels: usize,
        out_channels: usize,
        kernel_size: usize,
        padding: usize,
        stride: usize,
    ) -> Self {
        use ndarray_rand::RandomExt;
        use rand::distributions::Normal;

        let mut kernels = Array4::random(
            (out_channels, in_channels, kernel_size, kernel_size),
            Normal::new(0.0, 0.01).unwrap(),
        );
        kernels *= 0.1; // Xavier initialization

        let bias = Array2::zeros((out_channels, 1));

        Conv2D {
            kernels,
            bias,
            padding,
            stride,
            out_channels,
        }
    }

    /// Forward pass: Convolution operation
    pub fn forward(&self, input: &Array3<f64>) -> Array3<f64> {
        let (h, w, _) = input.dim();
        let kernel_size = self.kernels.dim().2;
        
        let out_h = (h + 2 * self.padding - kernel_size) / self.stride + 1;
        let out_w = (w + 2 * self.padding - kernel_size) / self.stride + 1;

        let mut output = Array3::zeros((out_h, out_w, self.out_channels));

        // Simple convolution (not optimized)
        for oc in 0..self.out_channels {
            for oh in 0..out_h {
                for ow in 0..out_w {
                    let mut sum = self.bias[[oc, 0]];
                    
                    for kh in 0..kernel_size {
                        for kw in 0..kernel_size {
                            let ih = oh * self.stride + kh;
                            let iw = ow * self.stride + kw;
                            
                            if ih < h && iw < w {
                                let pixel_val = input[[ih, iw, 0]];
                                let weight = self.kernels[[oc, 0, kh, kw]];
                                sum += pixel_val * weight;
                            }
                        }
                    }
                    
                    output[[oh, ow, oc]] = sum.max(0.0); // ReLU
                }
            }
        }

        output
    }

    /// Backward pass
    pub fn backward(&mut self, input: &Array3<f64>, d_output: &Array3<f64>, learning_rate: f64) {
        let (out_h, out_w, out_c) = d_output.dim();
        let kernel_size = self.kernels.dim().2;

        // Simplified gradient descent
        for oc in 0..out_c {
            for oh in 0..out_h {
                for ow in 0..out_w {
                    let grad = d_output[[oh, ow, oc]];
                    
                    for kh in 0..kernel_size {
                        for kw in 0..kernel_size {
                            let ih = oh * self.stride + kh;
                            let iw = ow * self.stride + kw;
                            
                            if ih < input.dim().0 && iw < input.dim().1 {
                                let pixel_val = input[[ih, iw, 0]];
                                self.kernels[[oc, 0, kh, kw]] -= learning_rate * grad * pixel_val;
                            }
                        }
                    }
                    
                    self.bias[[oc, 0]] -= learning_rate * grad;
                }
            }
        }
    }
}

/// MaxPool Layer
pub struct MaxPool {
    pub pool_size: usize,
    pub stride: usize,
}

impl MaxPool {
    pub fn new(pool_size: usize, stride: usize) -> Self {
        MaxPool { pool_size, stride }
    }

    pub fn forward(&self, input: &Array3<f64>) -> Array3<f64> {
        let (h, w, c) = input.dim();
        let out_h = (h + self.stride - self.pool_size) / self.stride;
        let out_w = (w + self.stride - self.pool_size) / self.stride;

        let mut output = Array3::zeros((out_h, out_w, c));

        for c_idx in 0..c {
            for oh in 0..out_h {
                for ow in 0..out_w {
                    let mut max_val = f64::NEG_INFINITY;
                    
                    for ph in 0..self.pool_size {
                        for pw in 0..self.pool_size {
                            let ih = oh * self.stride + ph;
                            let iw = ow * self.stride + pw;
                            
                            if ih < h && iw < w {
                                max_val = max_val.max(input[[ih, iw, c_idx]]);
                            }
                        }
                    }
                    
                    output[[oh, ow, c_idx]] = max_val;
                }
            }
        }

        output
    }
}

/// Simple CNN for MNIST
pub struct CNN {
    pub conv1: Conv2D,
    pub pool1: MaxPool,
    pub conv2: Conv2D,
    pub pool2: MaxPool,
    pub fc_weights: Array2<f64>,  // Flattened to 128
    pub fc_bias: Array2<f64>,
    pub output_weights: Array2<f64>, // 128 -> 10
    pub output_bias: Array2<f64>,
}

impl CNN {
    pub fn new() -> Self {
        CNN {
            conv1: Conv2D::new(1, 32, 3, 1, 1),    // 28x28x1 -> 28x28x32
            pool1: MaxPool::new(2, 2),              // 28x28x32 -> 14x14x32
            conv2: Conv2D::new(32, 64, 3, 1, 1),   // 14x14x32 -> 14x14x64
            pool2: MaxPool::new(2, 2),              // 14x14x64 -> 7x7x64
            fc_weights: {
                use ndarray_rand::RandomExt;
                use rand::distributions::Normal;
                Array2::random((7*7*64, 128), Normal::new(0.0, 0.01).unwrap()) * 0.1
            },
            fc_bias: Array2::zeros((128, 1)),
            output_weights: {
                use ndarray_rand::RandomExt;
                use rand::distributions::Normal;
                Array2::random((128, 10), Normal::new(0.0, 0.01).unwrap()) * 0.1
            },
            output_bias: Array2::zeros((10, 1)),
        }
    }

    /// Forward pass through entire CNN
    pub fn forward(&self, input: &Array3<f64>) -> Array2<f64> {
        // Conv -> ReLU -> MaxPool -> Conv -> ReLU -> MaxPool -> FC -> Output
        
        let c1_out = self.conv1.forward(input);    // 28x28x32
        let p1_out = self.pool1.forward(&c1_out);  // 14x14x32
        let c2_out = self.conv2.forward(&p1_out);  // 14x14x64
        let p2_out = self.pool2.forward(&c2_out);  // 7x7x64

        // Flatten: 7x7x64 = 3136
        let (h, w, c) = p2_out.dim();
        let mut flattened = Array2::zeros((h * w * c, 1));
        let mut idx = 0;
        for c_idx in 0..c {
            for h_idx in 0..h {
                for w_idx in 0..w {
                    flattened[[idx, 0]] = p2_out[[h_idx, w_idx, c_idx]];
                    idx += 1;
                }
            }
        }

        // FC layer
        let fc_out = self.fc_weights.dot(&flattened) + &self.fc_bias;
        let fc_relu = fc_out.mapv(|x| x.max(0.0)); // ReLU

        // Output layer
        let logits = self.output_weights.t().dot(&fc_relu) + &self.output_bias;
        
        // Softmax
        let max_logit = logits.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let exp_logits = logits.mapv(|x| (x - max_logit).exp());
        let sum_exp: f64 = exp_logits.iter().sum();
        let softmax = exp_logits / sum_exp;

        softmax
    }

    /// Get prediction
    pub fn predict(&self, input: &Array3<f64>) -> (usize, f64) {
        let output = self.forward(input);
        let mut max_prob = 0.0;
        let mut max_idx = 0;
        
        for i in 0..10 {
            if output[[i, 0]] > max_prob {
                max_prob = output[[i, 0]];
                max_idx = i;
            }
        }

        (max_idx, max_prob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conv2d_forward() {
        let conv = Conv2D::new(1, 3, 3, 1, 1);
        let input = Array3::ones((28, 28, 1));
        let output = conv.forward(&input);
        
        assert_eq!(output.dim().0, 28);
        assert_eq!(output.dim().1, 28);
        assert_eq!(output.dim().2, 3);
    }

    #[test]
    fn test_maxpool_forward() {
        let pool = MaxPool::new(2, 2);
        let input = Array3::from_shape_fn((4, 4, 1), |(h, w, _)| {
            (h * 4 + w) as f64
        });
        let output = pool.forward(&input);
        
        assert_eq!(output.dim().0, 2);
        assert_eq!(output.dim().1, 2);
    }

    #[test]
    fn test_cnn_predict() {
        let cnn = CNN::new();
        let input = Array3::from_elem((28, 28, 1), 0.5);
        let (pred, prob) = cnn.predict(&input);
        
        assert!(pred < 10);
        assert!(prob >= 0.0 && prob <= 1.0);
    }
}
