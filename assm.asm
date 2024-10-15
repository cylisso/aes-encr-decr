.code

fnGetSystemTimeAsFileTime proc
  mov eax, 7FFE0014h
  mov rax, [rax]
  mov [rcx], eax
  shr rax, 20h
  mov [rcx+4], eax
  ret
fnGetSystemTimeAsFileTime endp

end