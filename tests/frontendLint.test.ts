import {describe,expect,it} from 'vitest';
import {ESLint} from 'eslint';

describe('R53 actual frontend Hooks lint gate',()=>{
  it.each([
    ["import {useState} from 'react'; export function Example({ok}) { if(ok) useState(0); return null; }",'react-hooks/rules-of-hooks'],
    ["import {useEffect} from 'react'; export function Example({value}) { useEffect(()=>{console.log(value);},[]); return null; }",'react-hooks/exhaustive-deps'],
    ['export function Example(){debugger;return null;}','no-debugger']
  ])('rejects a broken fixture using the checked-in config: %s',async(code,rule)=>{
    const lint=new ESLint();const [result]=await lint.lintText(code,{filePath:'src/__lint_fixture.tsx'});
    expect(result.messages.some(message=>message.ruleId===rule&&message.severity===2)).toBe(true);
  });
  it('accepts correctly bounded Hook dependencies without warnings',async()=>{
    const [result]=await new ESLint().lintText("import {useEffect} from 'react'; export function Example({value}) { useEffect(()=>{console.log(value);},[value]); return null; }",{filePath:'src/__lint_fixture.tsx'});
    expect(result.errorCount).toBe(0);expect(result.warningCount).toBe(0);
  });
});
