const API = "http://127.0.0.1:8000";

export async function uploadEmail(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API}/api/upload-email`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || "Upload failed");
  }

  return response.json();
}