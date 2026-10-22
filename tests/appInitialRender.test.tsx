import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,expect,it} from 'vitest';
import App from '../src/App';

describe('startup regression: actual App hook/dependency initialization',()=>{
  it('renders its initial shell without a temporal-dead-zone exception',()=>{
    const markup=renderToStaticMarkup(<App/>);
    expect(markup.length).toBeGreaterThan(100);expect(markup).toContain('VKarmani');
  });
});
